//! Client handshake machine.

use std::{
    io::{Read, Write},
    marker::PhantomData,
};

#[cfg(feature = "deflate")]
use headers::{Header, HeaderMapExt};
use http::{
    header::HeaderName, HeaderMap, Request as HttpRequest, Response as HttpResponse, StatusCode,
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
use crate::extensions::{headers::SecWebsocketExtensions, ExtensionsError};
use crate::{
    error::{Error, ProtocolError, Result, SubProtocolError, UrlError},
    extensions::{Extensions, ExtensionsConfig},
    handshake::version_as_str,
    protocol::{Role, WebSocket, WebSocketConfig},
};

/// Client request type.
pub type Request = HttpRequest<()>;

/// Client response type.
pub type Response = HttpResponse<Option<Vec<u8>>>;

/// Client handshake role.
#[derive(Debug)]
pub struct ClientHandshake<S> {
    verify_data: VerifyData,
    config: Option<WebSocketConfig>,
    _marker: PhantomData<S>,
}

impl<S: Read + Write> ClientHandshake<S> {
    /// Initiate a client handshake.
    pub fn start(
        stream: S,
        request: Request,
        config: Option<WebSocketConfig>,
    ) -> Result<MidHandshake<Self>> {
        if request.method() != http::Method::GET {
            return Err(Error::Protocol(ProtocolError::WrongHttpMethod));
        }

        if request.version() < http::Version::HTTP_11 {
            return Err(Error::Protocol(ProtocolError::WrongHttpVersion));
        }

        // Check the URI scheme: only ws or wss are supported
        let _ = crate::client::uri_mode(request.uri())?;

        let subprotocols = extract_subprotocols_from_request(&request)?;
        #[cfg(feature = "deflate")]
        let caller_offered_extensions =
            request.headers().contains_key(SecWebsocketExtensions::name());

        // Convert and verify the `http::Request` and turn it into the request as per RFC.
        // Also extract the key from it (it must be present in a correct request).
        let (request, key) = generate_request(request, config.as_ref().map(|w| &w.extensions))?;

        let machine = HandshakeMachine::start_write(stream, request);

        let client = {
            let accept_key = derive_accept_key(key.as_ref());
            ClientHandshake {
                verify_data: VerifyData {
                    accept_key,
                    subprotocols,
                    #[cfg(feature = "deflate")]
                    caller_offered_extensions,
                },
                config,
                _marker: PhantomData,
            }
        };

        trace!("Client handshake initiated.");
        Ok(MidHandshake { role: client, machine })
    }
}

impl<S: Read + Write> HandshakeRole for ClientHandshake<S> {
    type IncomingData = Response;
    type InternalStream = S;
    type FinalResult = (WebSocket<S>, Response);
    fn stage_finished(
        &mut self,
        finish: StageResult<Self::IncomingData, Self::InternalStream>,
    ) -> Result<ProcessingResult<Self::InternalStream, Self::FinalResult>> {
        Ok(match finish {
            StageResult::DoneWriting(stream) => {
                ProcessingResult::Continue(HandshakeMachine::start_read(stream))
            }
            StageResult::DoneReading { stream, result, tail } => {
                let (result, extensions) = match self
                    .verify_data
                    .verify_response(result, self.config.as_ref().map(|c| &c.extensions))
                {
                    Ok(r) => r,
                    Err(Error::Http(mut e)) => {
                        *e.body_mut() = Some(tail);
                        return Err(Error::Http(e));
                    }
                    Err(e) => return Err(e),
                };

                debug!("Client handshake done.");
                let websocket = WebSocket::from_partially_read_with_extensions(
                    stream,
                    tail,
                    Role::Client,
                    self.config,
                    extensions,
                );
                ProcessingResult::Done((websocket, result))
            }
        })
    }
}

/// Verifies and generates a client WebSocket request from the original request and extracts a WebSocket key from it.
pub fn generate_request(
    mut request: Request,
    extensions: Option<&ExtensionsConfig>,
) -> Result<(Vec<u8>, String)> {
    let mut req = Vec::new();
    write!(
        req,
        "GET {path} {version}\r\n",
        path = request.uri().path_and_query().ok_or(Error::Url(UrlError::NoPathOrQuery))?.as_str(),
        version = version_as_str(request.version())?,
    )
    .unwrap();

    // Headers that must be present in a correct request.
    const KEY_HEADERNAME: &str = "Sec-WebSocket-Key";
    const WEBSOCKET_HEADERS: [&str; 5] =
        ["Host", "Connection", "Upgrade", "Sec-WebSocket-Version", KEY_HEADERNAME];

    // We must extract a WebSocket key from a properly formed request or fail if it's not present.
    let key = request
        .headers()
        .get(KEY_HEADERNAME)
        .ok_or_else(|| {
            Error::Protocol(ProtocolError::InvalidHeader(
                HeaderName::from_bytes(KEY_HEADERNAME.as_bytes()).unwrap().into(),
            ))
        })?
        .to_str()?
        .to_owned();

    // We must check that all necessary headers for a valid request are present. Note that we have to
    // deal with the fact that some apps seem to have a case-sensitive check for headers which is not
    // correct and should not considered the correct behavior, but it seems like some apps ignore it.
    // `http` by default writes all headers in lower-case which is fine (and does not violate the RFC)
    // but some servers seem to be poorely written and ignore RFC.
    //
    // See similar problem in `hyper`: https://github.com/hyperium/hyper/issues/1492
    let headers = request.headers_mut();
    for &header in &WEBSOCKET_HEADERS {
        let value = headers.remove(header).ok_or_else(|| {
            Error::Protocol(ProtocolError::InvalidHeader(
                HeaderName::from_bytes(header.as_bytes()).unwrap().into(),
            ))
        })?;
        write!(
            req,
            "{header}: {value}\r\n",
            header = header,
            value = value.to_str().map_err(|err| {
                Error::Utf8(format!("{err} for header name '{header}' with value: {value:?}"))
            })?
        )
        .unwrap();
    }

    #[cfg(feature = "deflate")]
    if let Some(header) = extensions
        .map(ExtensionsConfig::generate_offers)
        .map(SecWebsocketExtensions::new)
        .filter(|header| !header.is_empty())
    {
        headers.append(SecWebsocketExtensions::name(), header.header_value());
    }
    #[cfg(not(feature = "deflate"))]
    let _ = extensions;

    // Now we must ensure that the headers that we've written once are not anymore present in the map.
    // If they do, then the request is invalid (some headers are duplicated there for some reason).
    let websocket_headers_contains =
        |name| WEBSOCKET_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name));

    for (k, v) in headers {
        let mut name = k.as_str();

        // We have already written the necessary headers once (above) and removed them from the map.
        // If we encounter them again, then the request is considered invalid and error is returned.
        if websocket_headers_contains(name) {
            return Err(Error::Protocol(ProtocolError::InvalidHeader(k.clone().into())));
        }

        // Relates to the issue of some servers treating headers in a case-sensitive way, please see:
        // https://github.com/snapview/tungstenite-rs/pull/119 (original fix of the problem)
        if name == "sec-websocket-protocol" {
            name = "Sec-WebSocket-Protocol";
        }

        if name == "origin" {
            name = "Origin";
        }

        // Write header as raw bytes to support non-ASCII values.
        // HTTP headers are defined as octets (RFC 7230), not UTF-8 strings.
        req.extend_from_slice(name.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }

    req.extend_from_slice(b"\r\n");
    trace!("Request: {:?}", String::from_utf8_lossy(&req));
    Ok((req, key))
}

fn extract_subprotocols_from_request(request: &Request) -> Result<Option<Vec<String>>> {
    if let Some(subprotocols) = request.headers().get("Sec-WebSocket-Protocol") {
        Ok(Some(subprotocols.to_str()?.split(',').map(|s| s.trim().to_string()).collect()))
    } else {
        Ok(None)
    }
}

/// Information for handshake verification.
#[derive(Debug)]
struct VerifyData {
    /// Accepted server key.
    accept_key: String,

    /// Accepted subprotocols
    subprotocols: Option<Vec<String>>,

    /// Whether the request carried a `Sec-WebSocket-Extensions` header the
    /// caller wrote themselves.
    ///
    /// Only read when there is no [`ExtensionsConfig`], and in that case
    /// `generate_request` appends no offer of its own — so wherever this is
    /// consulted it means "the request as sent offered an extension".
    #[cfg(feature = "deflate")]
    caller_offered_extensions: bool,
}

impl VerifyData {
    pub fn verify_response(
        &self,
        response: Response,
        extensions: Option<&ExtensionsConfig>,
    ) -> Result<(Response, Extensions)> {
        // 1. If the status code received from the server is not 101, the
        // client handles the response per HTTP [RFC2616] procedures. (RFC 6455)
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::Http(response.into()));
        }

        let headers = response.headers();

        // 2. If the response lacks an |Upgrade| header field or the |Upgrade|
        // header field contains a value that is not an ASCII case-
        // insensitive match for the value "websocket", the client MUST
        // _Fail the WebSocket Connection_. (RFC 6455)
        if !headers
            .get("Upgrade")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        {
            return Err(Error::Protocol(ProtocolError::MissingUpgradeWebSocketHeader));
        }
        // 3.  If the response lacks a |Connection| header field or the
        // |Connection| header field doesn't contain a token that is an
        // ASCII case-insensitive match for the value "Upgrade", the client
        // MUST _Fail the WebSocket Connection_. (RFC 6455)
        if !headers
            .get("Connection")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("Upgrade"))
            .unwrap_or(false)
        {
            return Err(Error::Protocol(ProtocolError::MissingConnectionUpgradeHeader));
        }
        // 4.  If the response lacks a |Sec-WebSocket-Accept| header field or
        // the |Sec-WebSocket-Accept| contains a value other than the
        // base64-encoded SHA-1 of ... the client MUST _Fail the WebSocket
        // Connection_. (RFC 6455)
        if !headers.get("Sec-WebSocket-Accept").map(|h| h == &self.accept_key).unwrap_or(false) {
            return Err(Error::Protocol(ProtocolError::SecWebSocketAcceptKeyMismatch));
        }
        // 5.  If the response includes a |Sec-WebSocket-Extensions| header
        // field and this header field indicates the use of an extension
        // that was not present in the client's handshake (the server has
        // indicated an extension not requested by the client), the client
        // MUST _Fail the WebSocket Connection_. (RFC 6455)
        // Without a PMCE compiled in there is nothing to verify an agreement
        // against, so the header is ignored exactly as upstream ignores it.
        #[cfg(feature = "deflate")]
        let extensions = {
            let extensions_header =
                headers.typed_try_get::<SecWebsocketExtensions>().map_err(|_| {
                    ProtocolError::InvalidHeader(SecWebsocketExtensions::name().clone().into())
                })?;

            match (extensions_header, extensions) {
                (Some(agreed), Some(config)) => {
                    config.verify_agreed_on(agreed).map_err(ProtocolError::from)?
                }
                // The offer was the caller's own header, so there is no
                // agreement of ours to check the echo against — upstream
                // ignored it rather than failing.
                (Some(_), None) if self.caller_offered_extensions => Extensions::default(),
                // Nothing was offered at all. A header that names an extension
                // is then step 5 above; one that names none indicates none.
                (Some(agreed), None) => match agreed.iter().next() {
                    Some(unrequested) => {
                        return Err(Error::Protocol(
                            ExtensionsError::InvalidExtension(unrequested.name().into()).into(),
                        ))
                    }
                    None => Extensions::default(),
                },
                (None, _) => Extensions::default(),
            }
        };
        #[cfg(not(feature = "deflate"))]
        let extensions = {
            let _ = extensions;
            Extensions::default()
        };

        // 6.  If the response includes a |Sec-WebSocket-Protocol| header field
        // and this header field indicates the use of a subprotocol that was
        // not present in the client's handshake (the server has indicated a
        // subprotocol not requested by the client), the client MUST _Fail
        // the WebSocket Connection_. (RFC 6455)
        if headers.get("Sec-WebSocket-Protocol").is_none() && self.subprotocols.is_some() {
            return Err(Error::Protocol(ProtocolError::SecWebSocketSubProtocolError(
                SubProtocolError::NoSubProtocol,
            )));
        }

        if headers.get("Sec-WebSocket-Protocol").is_some() && self.subprotocols.is_none() {
            return Err(Error::Protocol(ProtocolError::SecWebSocketSubProtocolError(
                SubProtocolError::ServerSentSubProtocolNoneRequested,
            )));
        }

        if let Some(returned_subprotocol) = headers.get("Sec-WebSocket-Protocol") {
            if let Some(accepted_subprotocols) = &self.subprotocols {
                if !accepted_subprotocols.contains(&returned_subprotocol.to_str()?.to_string()) {
                    return Err(Error::Protocol(ProtocolError::SecWebSocketSubProtocolError(
                        SubProtocolError::InvalidSubProtocol,
                    )));
                }
            }
        }

        Ok((response, extensions))
    }
}

impl TryParse for Response {
    fn try_parse(buf: &[u8]) -> Result<Option<(usize, Self)>> {
        let mut hbuffer = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Response::new(&mut hbuffer);
        Ok(match req.parse(buf)? {
            Status::Partial => None,
            Status::Complete(size) => Some((size, Response::from_httparse(req)?)),
        })
    }
}

impl<'h, 'b: 'h> FromHttparse<httparse::Response<'h, 'b>> for Response {
    fn from_httparse(raw: httparse::Response<'h, 'b>) -> Result<Self> {
        if raw.version.expect("Bug: no HTTP version") < /*1.*/1 {
            return Err(Error::Protocol(ProtocolError::WrongHttpVersion));
        }

        let headers = HeaderMap::from_httparse(raw.headers)?;

        let mut response = Response::new(None);
        *response.status_mut() = StatusCode::from_u16(raw.code.expect("Bug: no HTTP status code"))?;
        *response.headers_mut() = headers;
        // TODO: httparse only supports HTTP 0.9/1.0/1.1 but not HTTP 2.0
        // so the only valid value we could get in the response would be 1.1.
        *response.version_mut() = http::Version::HTTP_11;

        Ok(response)
    }
}

/// Generate a random key for the `Sec-WebSocket-Key` header.
pub fn generate_key() -> String {
    // a base64-encoded (see Section 4 of [RFC4648]) value that,
    // when decoded, is 16 bytes in length (RFC 6455)
    let r: [u8; 16] = rand::random();
    data_encoding::BASE64.encode(&r)
}

#[cfg(test)]
mod tests {
    use super::{super::machine::TryParse, generate_key, generate_request, Response};
    use crate::client::IntoClientRequest;

    #[cfg(feature = "deflate")]
    #[test]
    fn response_extension_echoing_a_manual_offer_is_ignored() {
        // Mirror of the server-side config-`None` case: a client doing manual
        // negotiation has no `ExtensionsConfig`, so there is no agreement of
        // ours to check the echo against. Upstream ignores it, and treating the
        // absent config as an error instead would kill the handshake.
        use super::VerifyData;

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = crate::handshake::derive_accept_key(key.as_bytes());
        let verify = VerifyData {
            accept_key: accept.clone(),
            subprotocols: None,
            caller_offered_extensions: true,
        };

        let response = http::Response::builder()
            .status(101)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Accept", accept)
            .header("Sec-WebSocket-Extensions", "x-custom-extension")
            .body(None)
            .unwrap();

        verify.verify_response(response, None).expect("a manual offer must not be fatal");
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn absent_and_empty_extension_headers_agree_and_a_malformed_one_does_not() {
        // Records the four response shapes: absent, present but naming nothing,
        // undecodable, and decodable-but-invalid. The last two are both protocol
        // errors and they come from different places -- the header decode in this
        // function, and parameter validation inside `verify_agreed_on` -- so a
        // replacement that collapses them would go unnoticed by a test that only
        // asserted "some error".
        //
        // The first two are *observationally identical* here -- every arm of the
        // match below maps an empty agreed set to `Extensions::default()` -- so
        // this test has no power to tell them apart, and does not claim to. A
        // mutation replacing the `Option` with an unconditional `Some(parsed)`
        // passes it and the whole lib suite. What it does pin is the malformed
        // case. The absent-versus-empty distinction only becomes observable once
        // a response omitting a parameter local policy required must hard-fail
        // (RFC 7692 section 7); the discriminating test belongs with that
        // validator, not here.
        use super::VerifyData;
        use crate::{
            error::ProtocolError,
            extensions::{compression::deflate::DeflateConfig, ExtensionsConfig, ExtensionsError},
            Error,
        };

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = crate::handshake::derive_accept_key(key.as_bytes());
        let offered = ExtensionsConfig { permessage_deflate: Some(DeflateConfig::default()) };

        let negotiated = |extensions_header: Option<&str>| {
            let mut builder = http::Response::builder()
                .status(101)
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Accept", accept.clone());
            if let Some(value) = extensions_header {
                builder = builder.header("Sec-WebSocket-Extensions", value);
            }
            let verify = VerifyData {
                accept_key: accept.clone(),
                subprotocols: None,
                caller_offered_extensions: false,
            };
            verify
                .verify_response(builder.body(None).unwrap(), Some(&offered))
                .map(|(_, mut extensions)| extensions.per_message_compressor().is_some())
        };

        assert!(
            !negotiated(None).expect("an absent header is not an error"),
            "absent header must leave compression off"
        );
        assert!(
            !negotiated(Some("")).expect("a header naming no extension is not an error"),
            "present-but-empty header must agree with absent"
        );
        // A value `http` accepts but this header's grammar does not: the decode
        // in `verify_response` fails and names the header. Nothing else in the
        // crate covers this route.
        assert!(
            matches!(negotiated(Some(";x")), Err(Error::Protocol(ProtocolError::InvalidHeader(_)))),
            "an undecodable header must fail as InvalidHeader"
        );

        // Decodes cleanly -- `not-a-number` is a legal token -- so this one gets
        // past the decode and fails in parameter validation instead.
        match negotiated(Some("permessage-deflate; client_max_window_bits=not-a-number")) {
            Err(Error::Protocol(ProtocolError::InvalidExtensionsHeader(e))) => assert!(
                matches!(*e, ExtensionsError::MalformedExtension(_)),
                "expected a malformed-extension validation failure, got {e:?}"
            ),
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn response_extension_never_offered_is_rejected() {
        // RFC 6455 §4.1 step 5: an extension the client's handshake did not
        // contain is a MUST-fail. `client()` and `connect()` pass no config and
        // write no header, so this is the default path, not an exotic one.
        use super::VerifyData;
        use crate::{error::ProtocolError, extensions::ExtensionsError, Error};

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = crate::handshake::derive_accept_key(key.as_bytes());
        let verify = VerifyData {
            accept_key: accept.clone(),
            subprotocols: None,
            caller_offered_extensions: false,
        };

        let response = http::Response::builder()
            .status(101)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Accept", accept)
            .header("Sec-WebSocket-Extensions", "x-custom-extension")
            .body(None)
            .unwrap();

        let err = verify.verify_response(response, None).expect_err("§4.1 step 5 is a MUST-fail");
        assert!(
            matches!(
                &err,
                Error::Protocol(ProtocolError::InvalidExtensionsHeader(e))
                    if **e == ExtensionsError::InvalidExtension("x-custom-extension".into())
            ),
            "unexpected error: {err:?}"
        );
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn response_extension_header_naming_nothing_is_ignored() {
        // An empty header indicates no extension, so there is nothing the
        // client's handshake failed to contain.
        use super::VerifyData;

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = crate::handshake::derive_accept_key(key.as_bytes());
        let verify = VerifyData {
            accept_key: accept.clone(),
            subprotocols: None,
            caller_offered_extensions: false,
        };

        let response = http::Response::builder()
            .status(101)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Accept", accept)
            .header("Sec-WebSocket-Extensions", "")
            .body(None)
            .unwrap();

        verify.verify_response(response, None).expect("an empty header offers nothing to reject");
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn response_extension_outside_the_config_is_rejected() {
        // Pinning the half of this that is a design question rather than a
        // defect: once a config exists, it is treated as the whole offer, so an
        // extension the caller added to the request by hand is not recognised
        // and its echo fails the handshake. RFC 6455 §4.1 keys this on what the
        // client's handshake contained, which only the request headers know —
        // so honouring both would mean threading them into `VerifyData`.
        use super::VerifyData;
        use crate::{
            error::ProtocolError,
            extensions::{compression::deflate::DeflateConfig, ExtensionsConfig, ExtensionsError},
            Error,
        };

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = crate::handshake::derive_accept_key(key.as_bytes());
        let verify = VerifyData {
            accept_key: accept.clone(),
            subprotocols: None,
            caller_offered_extensions: true,
        };
        let config = ExtensionsConfig { permessage_deflate: Some(DeflateConfig::default()) };

        let response = http::Response::builder()
            .status(101)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Accept", accept)
            .header("Sec-WebSocket-Extensions", "x-hand-written-extension")
            .body(None)
            .unwrap();

        let err = verify
            .verify_response(response, Some(&config))
            .expect_err("an extension outside the config is not an agreement");
        assert!(
            matches!(
                &err,
                Error::Protocol(ProtocolError::InvalidExtensionsHeader(e))
                    if **e == ExtensionsError::InvalidExtension("x-hand-written-extension".into())
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn random_keys() {
        let k1 = generate_key();
        println!("Generated random key 1: {k1}");
        let k2 = generate_key();
        println!("Generated random key 2: {k2}");
        assert_ne!(k1, k2);
        assert_eq!(k1.len(), k2.len());
        assert_eq!(k1.len(), 24);
        assert_eq!(k2.len(), 24);
        assert!(k1.ends_with("=="));
        assert!(k2.ends_with("=="));
        assert!(k1[..22].find('=').is_none());
        assert!(k2[..22].find('=').is_none());
    }

    fn construct_expected(host: &str, key: &str) -> Vec<u8> {
        format!(
            "\
            GET /getCaseCount HTTP/1.1\r\n\
            Host: {host}\r\n\
            Connection: Upgrade\r\n\
            Upgrade: websocket\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Key: {key}\r\n\
            \r\n"
        )
        .into_bytes()
    }

    #[test]
    fn request_formatting() {
        let request = "ws://localhost/getCaseCount".into_client_request().unwrap();
        let (request, key) = generate_request(request, None).unwrap();
        let correct = construct_expected("localhost", &key);
        assert_eq!(&request[..], &correct[..]);
    }

    #[test]
    fn request_formatting_with_host() {
        let request = "wss://localhost:9001/getCaseCount".into_client_request().unwrap();
        let (request, key) = generate_request(request, None).unwrap();
        let correct = construct_expected("localhost:9001", &key);
        assert_eq!(&request[..], &correct[..]);
    }

    #[test]
    fn request_formatting_with_at() {
        let request = "wss://user:pass@localhost:9001/getCaseCount".into_client_request().unwrap();
        let (request, key) = generate_request(request, None).unwrap();
        let correct = construct_expected("localhost:9001", &key);
        assert_eq!(&request[..], &correct[..]);
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn request_with_compression() {
        use crate::extensions::{compression::deflate::DeflateConfig, ExtensionsConfig};

        let request = "ws://localhost/getCaseCount".into_client_request().unwrap();
        let (request, key) = generate_request(
            request,
            Some(&ExtensionsConfig {
                permessage_deflate: Some(DeflateConfig::default()),
                ..ExtensionsConfig::default()
            }),
        )
        .unwrap();
        let correct = format!(
            "\
            GET /getCaseCount HTTP/1.1\r\n\
            Host: {host}\r\n\
            Connection: Upgrade\r\n\
            Upgrade: websocket\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Key: {key}\r\n\
            sec-websocket-extensions: permessage-deflate; client_max_window_bits\r\n\
            \r\n",
            host = "localhost",
            key = key
        );
        assert_eq!(String::from_utf8(request).unwrap(), &correct[..]);
    }

    #[test]
    fn response_parsing() {
        const DATA: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let (_, resp) = Response::try_parse(DATA).unwrap().unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Type").unwrap(), &b"text/html"[..],);
    }

    #[test]
    fn invalid_custom_request() {
        let request = http::Request::builder().method("GET").body(()).unwrap();
        assert!(generate_request(request, None).is_err());
    }

    #[test]
    fn request_with_non_ascii_header() {
        use http::header::HeaderValue;

        let mut request = "ws://localhost/path".into_client_request().unwrap();

        // Add a header with non-ASCII value (UTF-8 encoded "Montréal")
        let non_ascii_value = HeaderValue::from_bytes(b"Montr\xc3\xa9al").unwrap();
        request.headers_mut().insert("X-City", non_ascii_value);

        // This should succeed, not fail with UTF-8 error
        let result = generate_request(request, None);
        assert!(result.is_ok(), "generate_request should accept non-ASCII header values");

        let (req_bytes, _key) = result.unwrap();

        // Verify the complete header with non-ASCII value is preserved in the output
        let expected_header = b"x-city: Montr\xc3\xa9al\r\n";
        assert!(
            req_bytes.windows(expected_header.len()).any(|window| window == expected_header),
            "Request should contain the complete non-ASCII header value"
        );
    }

    #[test]
    fn request_with_latin1_header() {
        use http::header::HeaderValue;

        let mut request = "ws://localhost/path".into_client_request().unwrap();

        // Add a header with ISO-8859-1 (Latin-1) encoded value
        // This is NOT valid UTF-8 but is valid for HTTP headers
        let latin1_value = HeaderValue::from_bytes(b"caf\xe9").unwrap(); // "café" in Latin-1
        request.headers_mut().insert("X-Test", latin1_value);

        // This should succeed
        let result = generate_request(request, None);
        assert!(result.is_ok(), "generate_request should accept Latin-1 header values");

        let (req_bytes, _key) = result.unwrap();

        // Verify the raw bytes are preserved in the output
        let expected_header = b"x-test: caf\xe9\r\n";
        assert!(
            req_bytes.windows(expected_header.len()).any(|window| window == expected_header),
            "Request should preserve the raw Latin-1 bytes"
        );
    }
}
