//! Server handshake machine.

use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    result::Result as StdResult,
};

#[cfg(feature = "deflate")]
use headers::HeaderMapExt;
use http::{
    header::HeaderValue, response::Builder, HeaderMap, Request as HttpRequest,
    Response as HttpResponse, StatusCode,
};
use httparse::Status;
use log::*;

use super::{
    derive_accept_key,
    headers::{FromHttparse, MAX_HEADERS},
    machine::{HandshakeMachine, StageResult, TryParse},
    HandshakeRole, MidHandshake, ProcessingResult,
};
#[cfg(feature = "deflate")]
use crate::extensions::headers::SecWebsocketExtensions;
use crate::{
    error::{Error, ProtocolError, Result},
    extensions::Extensions,
    handshake::version_as_str,
    protocol::{Role, WebSocket, WebSocketConfig},
};

/// Server request type.
pub type Request = HttpRequest<()>;

/// Server response type.
pub type Response = HttpResponse<()>;

/// Server error response type.
pub type ErrorResponse = HttpResponse<Option<String>>;

fn create_parts<T>(request: &HttpRequest<T>) -> Result<Builder> {
    if request.method() != http::Method::GET {
        return Err(Error::Protocol(ProtocolError::WrongHttpMethod));
    }

    if request.version() < http::Version::HTTP_11 {
        return Err(Error::Protocol(ProtocolError::WrongHttpVersion));
    }

    if !request
        .headers()
        .get("Connection")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split([' ', ',']).any(|p| p.eq_ignore_ascii_case("Upgrade")))
        .unwrap_or(false)
    {
        return Err(Error::Protocol(ProtocolError::MissingConnectionUpgradeHeader));
    }

    if !request
        .headers()
        .get("Upgrade")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return Err(Error::Protocol(ProtocolError::MissingUpgradeWebSocketHeader));
    }

    if !request.headers().get("Sec-WebSocket-Version").map(|h| h == "13").unwrap_or(false) {
        return Err(Error::Protocol(ProtocolError::MissingSecWebSocketVersionHeader));
    }

    let key = request
        .headers()
        .get("Sec-WebSocket-Key")
        .ok_or(Error::Protocol(ProtocolError::MissingSecWebSocketKey))?;

    if !is_valid_sec_websocket_key(key) {
        return Err(Error::Protocol(ProtocolError::InvalidSecWebSocketKey));
    }

    let builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .version(request.version())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Accept", derive_accept_key(key.as_bytes()));

    Ok(builder)
}

fn is_valid_sec_websocket_key(key: &HeaderValue) -> bool {
    if key.len() != 24 {
        return false;
    }

    let Ok(decoded) = data_encoding::BASE64.decode(key.as_bytes()) else {
        return false;
    };

    decoded.len() == 16
}

/// Create a response for the request.
pub fn create_response(request: &Request) -> Result<Response> {
    Ok(create_parts(request)?.body(())?)
}

/// Create a response for the request with a custom body.
pub fn create_response_with_body<T1, T2>(
    request: &HttpRequest<T1>,
    generate_body: impl FnOnce() -> T2,
) -> Result<HttpResponse<T2>> {
    Ok(create_parts(request)?.body(generate_body())?)
}

/// Write `response` to the stream `w`.
pub fn write_response<T>(mut w: impl io::Write, response: &HttpResponse<T>) -> Result<()> {
    writeln!(
        w,
        "{version} {status}\r",
        version = version_as_str(response.version())?,
        status = response.status()
    )?;

    for (k, v) in response.headers() {
        writeln!(w, "{}: {}\r", k, v.to_str()?)?;
    }

    writeln!(w, "\r")?;

    Ok(())
}

impl TryParse for Request {
    fn try_parse(buf: &[u8]) -> Result<Option<(usize, Self)>> {
        let mut hbuffer = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut hbuffer);
        Ok(match req.parse(buf)? {
            Status::Partial => None,
            Status::Complete(size) => Some((size, Request::from_httparse(req)?)),
        })
    }
}

impl<'h, 'b: 'h> FromHttparse<httparse::Request<'h, 'b>> for Request {
    fn from_httparse(raw: httparse::Request<'h, 'b>) -> Result<Self> {
        if raw.method.expect("Bug: no method in header") != "GET" {
            return Err(Error::Protocol(ProtocolError::WrongHttpMethod));
        }

        if raw.version.expect("Bug: no HTTP version") < /*1.*/1 {
            return Err(Error::Protocol(ProtocolError::WrongHttpVersion));
        }

        let headers = HeaderMap::from_httparse(raw.headers)?;

        let mut request = Request::new(());
        *request.method_mut() = http::Method::GET;
        *request.headers_mut() = headers;
        *request.uri_mut() = raw.path.expect("Bug: no path in header").parse()?;
        // TODO: httparse only supports HTTP 0.9/1.0/1.1 but not HTTP 2.0
        // so the only valid value we could get in the response would be 1.1.
        *request.version_mut() = http::Version::HTTP_11;

        Ok(request)
    }
}

/// The callback trait.
///
/// The callback is called when the server receives an incoming WebSocket
/// handshake request from the client. Specifying a callback allows you to analyze incoming headers
/// and add additional headers to the response that server sends to the client and/or reject the
/// connection based on the incoming headers.
pub trait Callback: Sized {
    /// Called whenever the server read the request from the client and is ready to reply to it.
    /// May return additional reply headers.
    /// Returning an error resulting in rejecting the incoming connection.
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> StdResult<Response, ErrorResponse>;
}

impl<F> Callback for F
where
    F: FnOnce(&Request, Response) -> StdResult<Response, ErrorResponse>,
{
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> StdResult<Response, ErrorResponse> {
        self(request, response)
    }
}

/// Stub for callback that does nothing.
#[derive(Clone, Copy, Debug)]
pub struct NoCallback;

impl Callback for NoCallback {
    fn on_request(
        self,
        _request: &Request,
        response: Response,
    ) -> StdResult<Response, ErrorResponse> {
        Ok(response)
    }
}

/// Server handshake role.
#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct ServerHandshake<S, C> {
    /// Callback which is called whenever the server read the request from the client and is ready
    /// to reply to it. The callback returns an optional headers which will be added to the reply
    /// which the server sends to the user.
    callback: Option<C>,
    /// WebSocket configuration.
    config: Option<WebSocketConfig>,
    /// Error code/flag. If set, an error will be returned after sending response to the client.
    error_response: Option<ErrorResponse>,
    // Negotiated extension context for server.
    extensions: Extensions,
    /// Internal stream type.
    _marker: PhantomData<S>,
}

impl<S: Read + Write, C: Callback> ServerHandshake<S, C> {
    /// Start server handshake. `callback` specifies a custom callback which the user can pass to
    /// the handshake, this callback will be called when the a websocket client connects to the
    /// server, you can specify the callback if you want to add additional header to the client
    /// upon join based on the incoming headers.
    pub fn start(stream: S, callback: C, config: Option<WebSocketConfig>) -> MidHandshake<Self> {
        trace!("Server handshake initiated.");
        MidHandshake {
            machine: HandshakeMachine::start_read(stream),
            role: ServerHandshake {
                callback: Some(callback),
                config,
                error_response: None,
                extensions: Extensions::default(),
                _marker: PhantomData,
            },
        }
    }
}

impl<S: Read + Write, C: Callback> HandshakeRole for ServerHandshake<S, C> {
    type IncomingData = Request;
    type InternalStream = S;
    type FinalResult = WebSocket<S>;

    fn stage_finished(
        &mut self,
        finish: StageResult<Self::IncomingData, Self::InternalStream>,
    ) -> Result<ProcessingResult<Self::InternalStream, Self::FinalResult>> {
        Ok(match finish {
            StageResult::DoneReading { stream, result, tail } => {
                if !tail.is_empty() {
                    return Err(Error::Protocol(ProtocolError::JunkAfterRequest));
                }

                #[cfg_attr(not(feature = "deflate"), allow(unused_mut))]
                let mut response = create_response(&result)?;
                // With no PMCE compiled in there is nothing to negotiate, so
                // the header is not parsed at all — upstream ignores it, and
                // RFC 6455 §9.1 permits that.
                //
                // A header the grammar rejects is treated as absent rather than
                // failing the handshake, which section 9.1 says a recipient
                // MUST do. Deliberate: `deflate` is opt-in, so failing here
                // would mean enabling a feature changes which requests the
                // server accepts, and ignoring it costs an uncompressed
                // connection rather than a broken one.
                #[cfg(feature = "deflate")]
                if let Some(extensions) =
                    result.headers().typed_try_get::<SecWebsocketExtensions>().ok().flatten()
                {
                    // `None` means defaults here as everywhere else in the
                    // crate — `accept()` passes it — and the default config
                    // declines every offer, which RFC 6455 §9.1 permits.
                    let extensions_config =
                        self.config.map(|config| config.extensions).unwrap_or_default();
                    let (extensions, agreed) = extensions_config
                        .accept_offers(&extensions)
                        .map_err(ProtocolError::from)?;

                    if let Some(agreed) = agreed {
                        response.headers_mut().typed_insert(agreed)
                    };
                    self.extensions = extensions;
                }

                let callback_result = if let Some(callback) = self.callback.take() {
                    callback.on_request(&result, response)
                } else {
                    Ok(response)
                };

                match callback_result {
                    Ok(response) => {
                        let mut output = vec![];
                        write_response(&mut output, &response)?;
                        ProcessingResult::Continue(HandshakeMachine::start_write(stream, output))
                    }

                    Err(resp) => {
                        if resp.status().is_success() {
                            return Err(Error::Protocol(ProtocolError::CustomResponseSuccessful));
                        }

                        self.error_response = Some(resp);
                        let resp = self.error_response.as_ref().unwrap();

                        let mut output = vec![];
                        write_response(&mut output, resp)?;

                        if let Some(body) = resp.body() {
                            output.extend_from_slice(body.as_bytes());
                        }

                        ProcessingResult::Continue(HandshakeMachine::start_write(stream, output))
                    }
                }
            }

            StageResult::DoneWriting(stream) => {
                if let Some(err) = self.error_response.take() {
                    debug!("Server handshake failed.");

                    let (parts, body) = err.into_parts();
                    let body = body.map(|b| b.as_bytes().to_vec());
                    return Err(Error::Http(http::Response::from_parts(parts, body).into()));
                } else {
                    debug!("Server handshake done.");
                    let websocket = WebSocket::from_raw_socket_with_extensions(
                        stream,
                        Role::Server,
                        self.config,
                        std::mem::take(&mut self.extensions),
                    );
                    ProcessingResult::Done(websocket)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{super::machine::TryParse, create_response, Request};
    use crate::error::{Error, ProtocolError};

    fn request_with_key(key: &str) -> Request {
        let data = format!(
            "\
            GET /script.ws HTTP/1.1\r\n\
            Host: foo.com\r\n\
            Connection: upgrade\r\n\
            Upgrade: websocket\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Key: {key}\r\n\
            \r\n"
        );

        let (_, req) = Request::try_parse(data.as_bytes()).unwrap().unwrap();
        req
    }

    fn assert_invalid_sec_websocket_key(key: &str) {
        let req = request_with_key(key);
        let err = create_response(&req).unwrap_err();
        assert!(matches!(err, Error::Protocol(ProtocolError::InvalidSecWebSocketKey)));
    }

    /// A duplex over a fixed request, so `accept` can be driven without a socket.
    struct MockStream {
        read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl std::io::Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.read, buf)
        }
    }

    impl std::io::Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Drives a bare `accept()` against a request carrying `offer`, and asserts
    /// the handshake completes with nothing echoed back.
    fn assert_bare_accept_ignores(offer: &str) {
        let request = format!(
            "GET /script.ws HTTP/1.1\r\n\
             Host: foo.com\r\n\
             Connection: upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Extensions: {offer}\r\n\
             \r\n"
        );
        let stream =
            MockStream { read: std::io::Cursor::new(request.into_bytes()), written: Vec::new() };

        let socket = crate::accept(stream)
            .unwrap_or_else(|e| panic!("offer {offer:?} must not fail the handshake: {e}"));
        let response = String::from_utf8_lossy(&socket.get_ref().written).to_ascii_lowercase();
        assert!(response.contains("101 switching protocols"), "offer {offer:?}: {response}");
        assert!(
            !response.contains("sec-websocket-extensions"),
            "offer {offer:?} must not be echoed: {response}"
        );
    }

    #[test]
    fn bare_accept_ignores_any_extensions_header() {
        // A bare `accept()` completes for every one of these in both builds.
        // With no PMCE compiled in the header is not parsed at all; with one
        // compiled in the default `ExtensionsConfig` has no
        // `permessage_deflate`, so every offer is declined without an echo; and
        // a header the grammar rejects outright is treated as absent rather
        // than failing. No wire form can fail a handshake upstream would
        // complete — hence the quoted value and the garbage.
        for offer in [
            // What every mainstream browser sends.
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; server_max_window_bits=\"10\"",
            "permessage-deflate; client_max_window_bits=8",
            "permessage-deflate; unknown_param=whatever",
            "permessage-deflate, permessage-deflate; server_no_context_takeover",
            "foo, bar; baz=2",
            "x-webkit-deflate-frame",
            ";;;",
            "=",
        ] {
            assert_bare_accept_ignores(offer);
        }
    }

    /// A callback that deletes the agreed extension header the server just wrote.
    #[cfg(feature = "deflate")]
    struct StripExtensions;

    #[cfg(feature = "deflate")]
    impl super::Callback for StripExtensions {
        fn on_request(
            self,
            _request: &Request,
            mut response: crate::handshake::server::Response,
        ) -> std::result::Result<
            crate::handshake::server::Response,
            crate::handshake::server::ErrorResponse,
        > {
            response.headers_mut().remove("Sec-WebSocket-Extensions");
            Ok(response)
        }
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn callback_stripping_the_agreed_header_leaves_compression_installed() {
        // Runtime extension state is installed before the callback runs, and the
        // callback owns the response and may remove any header. So a callback that
        // deletes `Sec-WebSocket-Extensions` produces a wire that says "no
        // compression agreed" over a socket that compresses: every message goes out
        // with RSV1 set to a peer that never agreed to read it.
        //
        // This asserts the divergence rather than the fix, because at this commit
        // the divergence is what happens. The compact implementation must make the
        // two commit together; when it does, this test inverts and the mutation that
        // proves it is re-separating the header write from the state install.
        use crate::extensions::{compression::deflate::DeflateConfig, ExtensionsConfig};

        let request = "GET /script.ws HTTP/1.1\r\n\
             Host: foo.com\r\n\
             Connection: upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Extensions: permessage-deflate\r\n\
             \r\n";
        let stream = MockStream {
            read: std::io::Cursor::new(request.as_bytes().to_vec()),
            written: Vec::new(),
        };
        let config = crate::protocol::WebSocketConfig {
            extensions: ExtensionsConfig { permessage_deflate: Some(DeflateConfig::default()) },
            ..Default::default()
        };

        let mut socket = crate::accept_hdr_with_config(stream, StripExtensions, Some(config))
            .expect("the handshake itself completes");

        let handshake_len = socket.get_ref().written.len();
        let response = String::from_utf8_lossy(&socket.get_ref().written).to_ascii_lowercase();
        assert!(response.contains("101 switching protocols"), "{response}");
        assert!(
            !response.contains("sec-websocket-extensions"),
            "the callback removed the header, so the wire agreed nothing: {response}"
        );

        socket.send(crate::Message::text("hello hello hello hello")).expect("send");
        let frame = &socket.get_ref().written[handshake_len..];
        let rsv1 = frame.first().expect("a frame was written") & 0x40 != 0;

        assert!(
            rsv1,
            "documents the divergence at this commit: the socket must be compressing \
             even though the response header was stripped. If this now fails, the \
             header write and the state install have been made atomic -- invert the \
             assertion and keep the test."
        );
    }

    #[test]
    fn request_parsing() {
        const DATA: &[u8] = b"GET /script.ws HTTP/1.1\r\nHost: foo.com\r\n\r\n";
        let (_, req) = Request::try_parse(DATA).unwrap().unwrap();
        assert_eq!(req.uri().path(), "/script.ws");
        assert_eq!(req.headers().get("Host").unwrap(), &b"foo.com"[..]);
    }

    #[test]
    fn request_replying() {
        const DATA: &[u8] = b"\
            GET /script.ws HTTP/1.1\r\n\
            Host: foo.com\r\n\
            Connection: upgrade\r\n\
            Upgrade: websocket\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            \r\n";
        let (_, req) = Request::try_parse(DATA).unwrap().unwrap();
        let response = create_response(&req).unwrap();

        assert_eq!(
            response.headers().get("Sec-WebSocket-Accept").unwrap(),
            b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".as_ref()
        );
    }

    #[test]
    fn test_invalid_websocket_key_empty() {
        assert_invalid_sec_websocket_key("");
    }

    #[test]
    fn test_invalid_websocket_key_too_long() {
        assert_invalid_sec_websocket_key("dGhlIHNhbXBsZSBub25jZQ==AAAAAAAAAA");
    }

    #[test]
    fn test_invalid_websocket_key_base64_symbol() {
        assert_invalid_sec_websocket_key("dGhlIHNhbXBsZSBub25jZQ!!");
    }

    #[test]
    fn test_invalid_websocket_key_decoded_length() {
        assert_invalid_sec_websocket_key("AAAAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn test_valid_websocket_key() {
        let req = request_with_key("dGhlIHNhbXBsZSBub25jZQ==");
        assert!(create_response(&req).is_ok());
    }
}
