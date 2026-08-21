use std::{num::NonZeroU8, str::FromStr};

use flate2::Compression;
use log::*;
use thiserror::Error;

use crate::{
    extensions::headers::{WebsocketExtensionParam, WebsocketProtocolExtension},
    protocol::Role,
};

/// Name of the extension as it appears in the Sec-WebSocket-Extensions header.
///
/// Defined by [RFC 7692 Section 7](https://tools.ietf.org/html/rfc7692#section-7)
pub const PER_MESSAGE_DEFLATE: &str = "permessage-deflate";

/// Extension option that determines whether the server should use the LZ77
/// sliding window from a sent frame for the subsequent frame.
///
/// Defined by [RFC 7692 Section 7.1.1.1](https://tools.ietf.org/html/rfc7692#section-7.1.1.1)
const SERVER_NO_CONTEXT_TAKEOVER: &str = "server_no_context_takeover";

/// Extension option that determines whether the client should use the LZ77
/// sliding window from a sent frame for the subsequent frame.
///
/// Defined by [RFC 7692 Section 7.1.1.2](https://tools.ietf.org/html/rfc7692#section-7.1.1.2)
const CLIENT_NO_CONTEXT_TAKEOVER: &str = "client_no_context_takeover";

/// Extension option that determines the server's max LZ77 sliding window size
/// when compressing outgoing frames.
///
/// Defined by [RFC 7692 Section 7.1.2.1](https://tools.ietf.org/html/rfc7692#section-7.1.2.1)
const SERVER_MAX_WINDOW_BITS: &str = "server_max_window_bits";

/// Extension option that determines the client's max LZ77 sliding window size
/// when compressing outgoing frames.
///
/// Defined by [RFC 7692 Section 7.1.2.2](https://tools.ietf.org/html/rfc7692#section-7.1.2.2)
const CLIENT_MAX_WINDOW_BITS: &str = "client_max_window_bits";

/// Allowed range of values for a [`SERVER_MAX_WINDOW_BITS`] or [`CLIENT_MAX_WINDOW_BITS`] parameter.
///
/// Defined by RFC 7692 Sections 7.1.2.1 and 7.1.2.2.
const ALLOWED_WINDOW_BITS: std::ops::RangeInclusive<NonZeroU8> =
    NonZeroU8::new(8).unwrap()..=NonZeroU8::new(15).unwrap();

/// The window sizes this implementation can compress with, as base-2 logarithms.
///
/// RFC 7692 allows 8 through 15; this range starts at 9 because the `flate2`
/// backends cannot deflate with an 8-bit window. A peer may still *offer* 8 —
/// see [`DeflateConfig::set_max_window_bits`], which rejects what it cannot
/// honour rather than silently widening it.
pub const SUPPORTED_WINDOW_BITS: std::ops::RangeInclusive<NonZeroU8> =
    NonZeroU8::new(9).unwrap()..=*ALLOWED_WINDOW_BITS.end();

/// Errors from `permessage-deflate` extension negotiation.
#[derive(Copy, Clone, Debug, Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum NegotiationError {
    /// Invalid `server_max_window_bits` value in a negotiation response.
    #[error("Invalid {SERVER_MAX_WINDOW_BITS} value in a negotiation response: {0}")]
    InvalidServerMaxWindowBitsValue(u8),
    /// Missing `server_max_window_bits` value in a negotiation response.
    #[error("Missing {SERVER_MAX_WINDOW_BITS} value in a negotiation response")]
    MissingServerMaxWindowBitsValue,
    /// Missing `server_no_context_takeover` value in a negotiation response.
    #[error("Missing {SERVER_NO_CONTEXT_TAKEOVER} value in a negotiation response")]
    MissingServerNoContextTakeover,
    /// The `client_max_window_bits` value in a negotiation response is not in [`SUPPORTED_WINDOW_BITS`].
    #[error("Unsupported {CLIENT_MAX_WINDOW_BITS} value")]
    UnsupportedClientMaxWindowBitsValue(u8),
}

/// Errors from parsing a single parameter in a `permessage-deflate` extension
/// directive.
#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ParameterError {
    /// Unknown parameter in a negotiation response.
    #[error("Unknown parameter in a negotiation response: {0}")]
    UnknownParameter(String),
    /// Duplicate parameter in a negotiation response.
    #[error("Duplicate parameter in a negotiation response: {0}")]
    DuplicateParameter(String),
    /// Parameter has an unexpected or invalid value.
    #[error("Invalid value {value} for parameter {name}")]
    InvalidParameterValue {
        /// The parameter whose value was rejected.
        name: &'static str,
        /// The value as it arrived, unparsed.
        value: String,
    },
}

/// Contents of a `permessage-deflate` Per-Message Compression Extension.
///
/// This represents the contents of a valid `permessage-deflate` directive found
/// in a `Sec-WebSocket-Extensions` header. Instances are produced by this
/// crate while parsing such a header, or by the [`Default`] implementation.
/// Consuming code can assume the fields here are valid according to
/// [RFC 7692 Section 7].
///
/// [RFC 7692 Section 7]: https://tools.ietf.org/html/rfc7692#section-7
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PermessageDeflateConfig {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    /// The `server_max_window_bits` parameter as described by [RFC 7692 Section 7.1.2.1].
    ///
    /// In a legal extension directive, if this parameter is present, it must
    /// have a value. A `None` value indicates the parameter is not present,
    /// while `Some(b)` indicates it is present with value `b`, where `b` is in
    /// the range [`ALLOWED_WINDOW_BITS`].
    ///
    /// [RFC 7692 Section 7.1.2.1]: https://tools.ietf.org/html/rfc7692#section-7.1.2.1
    server_max_window_bits: Option<NonZeroU8>,
    /// The `client_max_window_bits` parameter as described by [RFC 7692 Section 7.1.2.2].
    ///
    /// [RFC 7692 Section 7.1.2.2]: https://tools.ietf.org/html/rfc7692#section-7.1.2.2
    client_max_window_bits: ClientMaxWindowBits,
}

/// The state of a [`CLIENT_MAX_WINDOW_BITS`] parameter in an extension directive.
///
/// Unlike [`SERVER_MAX_WINDOW_BITS`], this parameter is legal with or without a
/// value, so a directive can say three different things about it.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum ClientMaxWindowBits {
    /// The parameter is not present in the directive.
    #[default]
    Absent,
    /// The parameter is present without a value.
    NoValue,
    /// The parameter is present with a value in [`ALLOWED_WINDOW_BITS`].
    Bits(NonZeroU8),
}

/// Client/server configuration for `permessage-deflate` support.
///
/// This holds configuration values for a client or server for the
/// `permessage-deflate` extension defined in [RFC 7692 Section 7]. This can be
/// used to produce a negotiation offer, or a response to one, as a
/// [`PermessageDeflateConfig`] for transmission to the peer.
///
/// [`set_max_window_bits`] is the only setting here that reduces per-connection
/// memory: it shrinks the sliding window, and a peer with a wider window can
/// always read a narrower stream, so a server may impose it without the client
/// agreeing. The `no_context_takeover` flags do **not** free anything — they
/// reset the compressor between messages and it keeps its buffers — so they
/// trade compression ratio and CPU, not memory.
///
/// [`set_max_window_bits`]: DeflateConfig::set_max_window_bits
///
/// [RFC 7692 Section 7]: https://tools.ietf.org/html/rfc7692#section-7
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DeflateConfig {
    /// How hard to try to compress outgoing data.
    pub compression: Compression,
    /// If set, indicates that server compression of a subsequent message won't
    /// reuse the context window of the previous one.
    pub server_no_context_takeover: bool,
    /// If set, indicates that client compression of a subsequent message won't
    /// reuse the context window of the previous one.
    pub client_no_context_takeover: bool,
    // Both windows are in `ALLOWED_WINDOW_BITS`, and whichever of the two is
    // *this* end's — `server_` for a server, `client_` for a client — is
    // further in `SUPPORTED_WINDOW_BITS`, because flate2 cannot deflate with an
    // 8-bit window. The other is the peer's and is only ever inflated with,
    // where a window at least as large as the sender's is always correct, so
    // `DeflateContext::new` raises it to the smallest flate2 accepts. Each
    // negotiation path asserts its own half: `accept_offer` for a server,
    // `accept_response` for a client. A `DeflateConfig` does not carry its
    // role, so this cannot be stated per field.
    /// The window the server compresses with. In `ALLOWED_WINDOW_BITS`.
    server_max_window_bits: NonZeroU8,
    /// The window the client compresses with. In `ALLOWED_WINDOW_BITS`.
    client_max_window_bits: NonZeroU8,
}

/// Error type returned by [`DeflateConfig::set_max_window_bits`].
#[derive(Copy, Clone, Debug, Error)]
#[error("this implementation supports max window bits in {SUPPORTED_WINDOW_BITS:?}")]
pub struct DeflateInvalidMaxWindowBits;

/// Error type returned by [`DeflateConfig::set_compression_level`].
#[derive(Copy, Clone, Debug, Error)]
#[error("compression level must be in 0..=9")]
pub struct DeflateInvalidCompressionLevel;

impl DeflateConfig {
    /// Constructs a new [`DeflateConfig`] with default parameters.
    pub fn new() -> Self {
        Self {
            compression: Compression::default(),
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: *SUPPORTED_WINDOW_BITS.end(),
            client_max_window_bits: *SUPPORTED_WINDOW_BITS.end(),
        }
    }

    #[allow(missing_docs)]
    #[inline]
    pub fn server_max_window_bits(&self) -> NonZeroU8 {
        self.server_max_window_bits
    }

    #[allow(missing_docs)]
    #[inline]
    pub fn client_max_window_bits(&self) -> NonZeroU8 {
        self.client_max_window_bits
    }

    /// Limits the maximum number of window bits used by a peer during compression.
    ///
    /// Sets the size of the sliding window that compressed streams sent by the
    /// given role will use. The `bits` value is the base-2 logarithm of the
    /// window size, and must be in the range [`SUPPORTED_WINDOW_BITS`]. If not,
    /// an error is returned.
    #[inline]
    pub fn set_max_window_bits(
        mut self,
        role: Role,
        bits: u8,
    ) -> Result<Self, DeflateInvalidMaxWindowBits> {
        let which = match role {
            Role::Server => &mut self.server_max_window_bits,
            Role::Client => &mut self.client_max_window_bits,
        };

        let bits = NonZeroU8::new(bits)
            .filter(|bits| SUPPORTED_WINDOW_BITS.contains(bits))
            .ok_or(DeflateInvalidMaxWindowBits)?;

        *which = bits;
        Ok(self)
    }

    /// Sets [`server_no_context_takeover`] or [`client_no_context_takeover`].
    ///
    /// The fields are public; this is just a convenience for builder-style usage.
    ///
    /// [`server_no_context_takeover`]: DeflateConfig::server_no_context_takeover
    /// [`client_no_context_takeover`]: DeflateConfig::client_no_context_takeover
    #[inline]
    pub fn set_no_context_takeover(mut self, role: Role, no_context_takeover: bool) -> Self {
        let which = match role {
            Role::Server => &mut self.server_no_context_takeover,
            Role::Client => &mut self.client_no_context_takeover,
        };
        *which = no_context_takeover;
        self
    }

    /// Sets how hard to try to compress outgoing data, 0 (none) to 9 (best).
    ///
    /// The [`compression`] field is public, but its type comes from `flate2`,
    /// which this crate does not re-export — so a caller outside the crate
    /// cannot name it. This takes the level as an integer instead, the same
    /// shape as the two knobs beside it, and adds no dependency to the caller.
    ///
    /// Rejects anything above 9 rather than clamping, because nothing below
    /// this validates: `flate2::Compression::new` accepts any `u32`, and the
    /// zlib-rs backend only `debug_assert!`s the range, so an out-of-range
    /// level is silent in a release build.
    ///
    /// Local only — it never appears in a negotiation offer or response.
    ///
    /// [`compression`]: DeflateConfig::compression
    #[inline]
    pub fn set_compression_level(
        mut self,
        level: u32,
    ) -> Result<Self, DeflateInvalidCompressionLevel> {
        if level > 9 {
            return Err(DeflateInvalidCompressionLevel);
        }
        self.compression = Compression::new(level);
        Ok(self)
    }

    /// Produces a [`PermessageDeflateConfig`] to send as a client offer to a server.
    ///
    /// The returned value can be serialized as a [`WebsocketProtocolExtension`]
    /// for inclusion in a
    /// [`SecWebsocketExtensions`](crate::extensions::headers::SecWebsocketExtensions)
    /// header.
    pub fn as_offer(&self) -> PermessageDeflateConfig {
        let Self {
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
            compression: _,
        } = *self;

        // Only offer `server_max_window_bits` when we want a smaller window
        // than the max: a server that doesn't recognize the parameter declines
        // the whole offer. RFC 7692 §7.1.2.1.
        let server_max_window_bits = (server_max_window_bits != *ALLOWED_WINDOW_BITS.end())
            .then_some(server_max_window_bits);

        PermessageDeflateConfig {
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits: if client_max_window_bits == *ALLOWED_WINDOW_BITS.end() {
                ClientMaxWindowBits::NoValue
            } else {
                ClientMaxWindowBits::Bits(client_max_window_bits)
            },
        }
    }

    /// Receives a negotiation offer from the client and computes the agreed-upon parameters.
    ///
    /// This should be called on the [`DeflateConfig`] representing the server's
    /// initial configuration with the offered parameters from the client as the
    /// argument. If this method returns `Some`, the resulting `DeflateConfig`
    /// may be used as the "agreed parameters" for the connection, and the
    /// resulting [`PermessageDeflateConfig`] should be transmitted to the
    /// client as the response to the offer.
    ///
    /// Note that this method may need to be called multiple times. Per [RFC 7692 Section 5]:
    ///
    ///   A client may also offer multiple PMCE choices to the server by
    ///   including multiple elements in the "Sec-WebSocket-Extensions" header,
    ///   one for each PMCE offered.  This set of elements MAY include multiple
    ///   PMCEs with the same extension name to offer the possibility to use the
    ///   same algorithm with different configuration parameters.  The order of
    ///   elements is important as it specifies the client's preference.  An
    ///   element preceding another element has higher preference.  It is
    ///   recommended that a server accepts PMCEs with higher preference if the
    ///   server supports them.
    ///
    /// [RFC 7692 Section 5]: https://tools.ietf.org/html/rfc7692#section-5
    /// Decides a server's response to a client's `permessage-deflate` offer.
    ///
    /// Returns the configuration to run and the parameters to echo, or `None` to
    /// decline. The server's own configuration acts as a floor: a flag set here
    /// is imposed whether or not the client asked for it, and a window this
    /// build cannot compress with is declined rather than silently widened.
    pub fn accept_offer(
        &self,
        client: PermessageDeflateConfig,
    ) -> Option<(DeflateConfig, PermessageDeflateConfig)> {
        // `None` declines the offer. Of RFC 7692 §7's four decline conditions
        // this covers only the last, an unsupportable configuration; undefined,
        // repeated and invalid parameters are rejected earlier, in
        // `parse_params` and `accept_offers`.
        let Self {
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
            compression,
        } = *self;

        // Required: RFC 7692 §7.1.1.1 defines accepting an offer that carries
        // this parameter as echoing it, and returning `Some` here is that
        // acceptance. Dropping the second term would emit an accepting response
        // that omits the parameter.
        let server_no_context_takeover =
            server_no_context_takeover || client.server_no_context_takeover;
        // Discretionary: §7.1.1.2 lets the server ignore the client's offered
        // parameter instead. Honouring it is our choice, not compliance.
        let client_no_context_takeover =
            client_no_context_takeover || client.client_no_context_takeover;

        // The response echoes the same or a smaller window than the offer.
        // RFC 7692 §7.1.2.1.
        let (server_max_window_bits, response_server_max_window_bits) = match client
            .server_max_window_bits
        {
            None => (server_max_window_bits, None),
            Some(requested_max) => {
                // Decline the offer if the client is requesting a window that
                // is smaller than we can support.
                if !SUPPORTED_WINDOW_BITS.contains(&requested_max) {
                    debug!("declining offer: {SERVER_MAX_WINDOW_BITS} is smaller than can be supported");
                    return None;
                }
                // It's fine if the client indicated support for a larger window
                // that we can provide; we just downgrade that to our max.
                let bits = requested_max.min(server_max_window_bits);
                (bits, Some(bits))
            }
        };

        let client_max_window_bits = match client.client_max_window_bits {
            ClientMaxWindowBits::Absent => {
                if client_max_window_bits != *ALLOWED_WINDOW_BITS.end() {
                    // RFC 7692 §7.1.2.2 forbids echoing the parameter when the
                    // offer omitted it, so a locally limited window has no way
                    // to be signalled: respect the config and decline.
                    debug!("declining offer without {CLIENT_MAX_WINDOW_BITS} (locally limited to {client_max_window_bits})");
                    return None;
                }
                client_max_window_bits
            }
            ClientMaxWindowBits::NoValue => {
                // The client supports the parameter so we can use our configured value.
                client_max_window_bits
            }
            // No lower bound — the peer's compressor, which we only inflate with.
            ClientMaxWindowBits::Bits(client_max) => client_max.min(client_max_window_bits),
        };

        // Server side of the invariant on the fields; `accept_response` asserts the other.
        debug_assert!(SUPPORTED_WINDOW_BITS.contains(&server_max_window_bits));
        debug_assert!(ALLOWED_WINDOW_BITS.contains(&client_max_window_bits));

        let connection_config = DeflateConfig {
            compression,
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
        };

        let offer_response = PermessageDeflateConfig {
            server_no_context_takeover,
            client_no_context_takeover,

            server_max_window_bits: response_server_max_window_bits,
            client_max_window_bits: if client_max_window_bits == *ALLOWED_WINDOW_BITS.end() {
                ClientMaxWindowBits::Absent
            } else {
                ClientMaxWindowBits::Bits(client_max_window_bits)
            },
        };

        Some((connection_config, offer_response))
    }

    /// Receives a response from the server and checks it against the requested context.
    ///
    /// This should be called on the [`DeflateConfig`] representing the client's
    /// configuration, with the response from the server as the argument. An
    /// `Ok` result will indicate the set of options the client should use for
    /// the remainder of the connection.
    /// Checks a server's response against the offer a client sent.
    ///
    /// Returns the configuration to run, or an error if the response is not one
    /// this client can honour — a parameter it never offered, or a window
    /// outside what this build supports.
    pub fn accept_response(
        self,
        server: PermessageDeflateConfig,
    ) -> Result<Self, NegotiationError> {
        let Self {
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
            compression,
        } = self;

        let server_no_context_takeover =
            if server_no_context_takeover && !server.server_no_context_takeover {
                // The client requested no server takeover but the server didn't
                // agree to that.
                return Err(NegotiationError::MissingServerNoContextTakeover);
            } else {
                server.server_no_context_takeover
            };

        // The server can force client-side takeover off. RFC 7692 §7.1.1.2.
        let client_no_context_takeover =
            client_no_context_takeover || server.client_no_context_takeover;

        let server_max_window_bits = {
            // An accepted offer echoes the same or a smaller value than the
            // one we asked for. RFC 7692 §7.1.2.1.
            let default_server_max_bits = || {
                (server_max_window_bits == *ALLOWED_WINDOW_BITS.end())
                    .then_some(server_max_window_bits)
            };
            let received = server
                .server_max_window_bits
                .or_else(default_server_max_bits)
                .ok_or(NegotiationError::MissingServerMaxWindowBitsValue)?;

            if received > server_max_window_bits {
                return Err(NegotiationError::InvalidServerMaxWindowBitsValue(received.get()));
            }

            // No lower bound — the peer's compressor. Recorded unclamped so this
            // equals what was negotiated, which is what RFC 7692 §7.1.2.1 defines.
            received
        };

        let client_max_window_bits = match server.client_max_window_bits {
            // Absent means the server accepts a full 32,768-byte window
            // (RFC 7692 §7.1.2.2). Present-but-empty is arguably not legal at
            // all — §7.1.2.2 gives the response-side parameter a `1*DIGIT`
            // value, and §7 makes an invalid response value a client MUST-fail
            // — so this arm knowingly tolerates a non-conforming response
            // rather than reading a meaning into it.
            ClientMaxWindowBits::Absent | ClientMaxWindowBits::NoValue => client_max_window_bits,
            ClientMaxWindowBits::Bits(received) => {
                // A value caps the window we compress with, and §7.1.2.2
                // requires it be "equal to or smaller than the received
                // value" — so an over-large one is invalid, which §7 makes a
                // client MUST-fail. Hence the error rather than a clamp.
                if !SUPPORTED_WINDOW_BITS.contains(&received) {
                    return Err(NegotiationError::UnsupportedClientMaxWindowBitsValue(
                        received.get(),
                    ));
                }

                if received > client_max_window_bits {
                    // The server sent us a larger value back than the one we sent.
                    return Err(NegotiationError::UnsupportedClientMaxWindowBitsValue(
                        received.get(),
                    ));
                }

                client_max_window_bits.min(received)
            }
        };

        // Client side of the same invariant.
        debug_assert!(ALLOWED_WINDOW_BITS.contains(&server_max_window_bits));
        debug_assert!(SUPPORTED_WINDOW_BITS.contains(&client_max_window_bits));

        Ok(Self {
            compression,
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
        })
    }
}

impl PermessageDeflateConfig {
    /// Generate the corresponding [`WebsocketProtocolExtension`] value.
    fn as_extension(&self) -> WebsocketProtocolExtension {
        let Self {
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
        } = self;

        let context_takeovers = [
            server_no_context_takeover.then_some(SERVER_NO_CONTEXT_TAKEOVER),
            client_no_context_takeover.then_some(CLIENT_NO_CONTEXT_TAKEOVER),
        ]
        .into_iter()
        .flatten();

        let max_window_bits = [
            server_max_window_bits.map(|bits| (SERVER_MAX_WINDOW_BITS, Some(bits.to_string()))),
            match client_max_window_bits {
                ClientMaxWindowBits::Absent => None,
                ClientMaxWindowBits::NoValue => Some((CLIENT_MAX_WINDOW_BITS, None)),
                ClientMaxWindowBits::Bits(bits) => {
                    Some((CLIENT_MAX_WINDOW_BITS, Some(bits.to_string())))
                }
            },
        ]
        .into_iter()
        .flatten();

        WebsocketProtocolExtension::new(
            PER_MESSAGE_DEFLATE,
            context_takeovers
                .zip(std::iter::repeat(None))
                .chain(max_window_bits)
                .map(|(name, value)| WebsocketExtensionParam::new(name, value)),
        )
    }

    /// Parses the extension parameter list for a `Sec-WebSocket-Extensions` header.
    /// Parses an extension's parameter list into a validated configuration.
    ///
    /// The caller that owns the HTTP handshake needs this: it has the parameters
    /// from a `Sec-WebSocket-Extensions` offer and has to turn them into
    /// something it can decide on. Fields on the result are valid per RFC 7692
    /// section 7.
    pub fn parse_params<'p>(
        params: impl IntoIterator<Item = &'p WebsocketExtensionParam>,
    ) -> Result<Self, ParameterError> {
        let mut this = Self {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: None,
            client_max_window_bits: ClientMaxWindowBits::Absent,
        };

        fn apply<'a>(
            this: &mut PermessageDeflateConfig,
            param: ParamName,
            value: Option<&'a str>,
        ) -> Result<(), Option<&'a str>> {
            match param {
                ParamName::NoContextTakeover(role) => {
                    if value.is_some() {
                        return Err(value);
                    }
                    *match role {
                        Role::Server => &mut this.server_no_context_takeover,
                        Role::Client => &mut this.client_no_context_takeover,
                    } = true;
                    Ok(())
                }

                ParamName::MaxWindowBits(role) => {
                    let bits = value
                        .map(|bits| {
                            // Deliberately lenient: leading zeros parse, which
                            // the RFC disallows but no compliant peer sends.
                            bits.parse()
                                .ok()
                                .filter(|bits| ALLOWED_WINDOW_BITS.contains(bits))
                                .ok_or(value)
                        })
                        .transpose()?;
                    // The two are not symmetric: `server_max_window_bits` must
                    // carry a value, `client_max_window_bits` may stand alone.
                    // RFC 7692 §7.1.2.1, §7.1.2.2.
                    match role {
                        Role::Server => {
                            this.server_max_window_bits = Some(bits.ok_or(value)?);
                        }
                        Role::Client => {
                            this.client_max_window_bits =
                                bits.map_or(ClientMaxWindowBits::NoValue, ClientMaxWindowBits::Bits)
                        }
                    };
                    Ok(())
                }
            }
        }

        // Set of seen parameters represented as a bit mask.
        let mut seen_params = 0u8;

        for extension_param in params {
            let (name, value) = (extension_param.name(), extension_param.value());
            let param: ParamName = name.parse()?;

            let seen_flag = 1 << param.ordinal();
            if seen_params & seen_flag != 0 {
                return Err(ParameterError::DuplicateParameter(name.to_string()));
            }

            apply(&mut this, param, value).map_err(|value| {
                ParameterError::InvalidParameterValue {
                    name: param.name(),
                    value: value.unwrap_or_default().to_string(),
                }
            })?;

            seen_params |= seen_flag;
        }

        Ok(this)
    }
}

impl Default for DeflateConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&PermessageDeflateConfig> for WebsocketProtocolExtension {
    fn from(value: &PermessageDeflateConfig) -> Self {
        value.as_extension()
    }
}

impl From<PermessageDeflateConfig> for WebsocketProtocolExtension {
    fn from(value: PermessageDeflateConfig) -> Self {
        value.as_extension()
    }
}

#[derive(Copy, Clone)]
enum ParamName {
    NoContextTakeover(Role),
    MaxWindowBits(Role),
}

impl FromStr for ParamName {
    type Err = ParameterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            CLIENT_MAX_WINDOW_BITS => Self::MaxWindowBits(Role::Client),
            SERVER_MAX_WINDOW_BITS => Self::MaxWindowBits(Role::Server),
            CLIENT_NO_CONTEXT_TAKEOVER => Self::NoContextTakeover(Role::Client),
            SERVER_NO_CONTEXT_TAKEOVER => Self::NoContextTakeover(Role::Server),
            name => return Err(ParameterError::UnknownParameter(name.to_string())),
        })
    }
}

impl ParamName {
    fn ordinal(&self) -> u8 {
        match self {
            Self::NoContextTakeover(role) => *role as u8,
            Self::MaxWindowBits(role) => 2 + *role as u8,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            ParamName::NoContextTakeover(Role::Server) => SERVER_NO_CONTEXT_TAKEOVER,
            ParamName::NoContextTakeover(Role::Client) => CLIENT_NO_CONTEXT_TAKEOVER,
            ParamName::MaxWindowBits(Role::Server) => SERVER_MAX_WINDOW_BITS,
            ParamName::MaxWindowBits(Role::Client) => CLIENT_MAX_WINDOW_BITS,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::extensions::headers::SecWebsocketExtensions;
    use headers::Header;
    use http::HeaderValue;

    use super::*;

    #[test]
    fn set_compression_level_maps_onto_flate2_and_rejects_out_of_range() {
        // The point of the setter is that a caller outside this crate cannot name
        // `flate2::Compression`, so the mapping is what has to be right.
        for level in 0..=9u32 {
            assert_eq!(
                DeflateConfig::default()
                    .set_compression_level(level)
                    .expect("0..=9 is in range")
                    .compression,
                Compression::new(level),
                "level {level} must map to the same flate2 level"
            );
        }
        // Rejected, not clamped: nothing below this validates, so silently
        // accepting 10 as 9 would hide a caller's mistake instead of naming it.
        assert!(DeflateConfig::default().set_compression_level(10).is_err());
        assert!(DeflateConfig::default().set_compression_level(u32::MAX).is_err());
    }

    #[test]
    fn set_compression_level_leaves_the_negotiated_parameters_alone() {
        // It is a local setting: it must not leak into an offer, because nothing
        // in RFC 7692 carries a compression level.
        let base = DeflateConfig::default();
        let tuned = base.set_compression_level(9).expect("9 is in range");
        assert_eq!(tuned.as_offer(), base.as_offer(), "the offer must not change");
        assert_eq!(tuned.server_max_window_bits(), base.server_max_window_bits());
        assert_eq!(tuned.client_max_window_bits(), base.client_max_window_bits());
        assert_eq!(tuned.server_no_context_takeover, base.server_no_context_takeover);
        assert_eq!(tuned.client_no_context_takeover, base.client_no_context_takeover);
    }

    #[test]
    fn agreed_eight_bit_peer_window_inflates() {
        // `server_max_window_bits` is the server's compressor, so a client only
        // inflates with it: 8 is legal (RFC 7692 §7.1.2.1) and a conforming
        // server may send it unprompted, so refusing kills a valid connection.
        // Accepting is safe only because `DeflateContext::new` clamps — both
        // `Decompress::new_with_window_bits` and its compress twin assert
        // 9..=15, which is also why the peer below compresses at 9 and why
        // negotiation keeps our own compressor there.
        let client = DeflateConfig::new();
        let agreed = client
            .accept_response(PermessageDeflateConfig {
                server_max_window_bits: Some(8.try_into().unwrap()),
                ..Default::default()
            })
            .expect("8 is a legal server window");
        assert_eq!(agreed.server_max_window_bits().get(), 8);

        let mut us =
            crate::extensions::compression::deflate::DeflateContext::new(Role::Client, agreed);

        let peer_config = DeflateConfig::new()
            .set_max_window_bits(Role::Server, 9.try_into().unwrap())
            .expect("9 is supported");
        let mut peer =
            crate::extensions::compression::deflate::DeflateContext::new(Role::Server, peer_config);

        let payload =
            bytes::Bytes::from_static(b"the quick brown fox jumps over the lazy dog, twice over");
        let compressed = peer.compress(&payload).expect("peer compresses");
        let inflated = us.decompress(&compressed, true, usize::MAX).expect("we inflate");
        assert_eq!(&inflated[..], &payload[..]);
    }

    #[test]
    fn accept_offer_allows_client_window_of_eight() {
        // Mirror of the response case: `client_max_window_bits` caps the
        // *client's* compressor, so the server only inflates with it. Declining
        // was conformant but forfeited compression on a legal offer — and the
        // accept path is only safe because `DeflateContext::new` clamps the
        // inflate window; without that this is a remote panic, since
        // `Decompress::new_with_window_bits` asserts 9..=15.
        let server = DeflateConfig::new();
        let (agreed, response) = server
            .accept_offer(PermessageDeflateConfig {
                client_max_window_bits: ClientMaxWindowBits::Bits(8.try_into().unwrap()),
                ..Default::default()
            })
            .expect("8 is a legal client window");
        assert_eq!(agreed.client_max_window_bits().get(), 8);
        assert_eq!(
            response.client_max_window_bits,
            ClientMaxWindowBits::Bits(8.try_into().unwrap())
        );

        // Must not panic — this is the constructor the decline was shielding.
        let mut us =
            crate::extensions::compression::deflate::DeflateContext::new(Role::Server, agreed);

        // The peer compresses at 9 because a true 8-bit stream cannot be
        // built here: `Compress::new_with_window_bits` carries the same
        // 9..=15 assert, and a C zlib peer promotes a requested 8 to 9 in
        // `deflateInit2` anyway. What is under test is that our inflate side
        // survives having negotiated 8.
        let peer_config = DeflateConfig::new()
            .set_max_window_bits(Role::Client, 9.try_into().unwrap())
            .expect("9 is supported");
        let mut peer =
            crate::extensions::compression::deflate::DeflateContext::new(Role::Client, peer_config);

        let payload = bytes::Bytes::from_static(b"round-trips across an 8-bit peer window");
        let compressed = peer.compress(&payload).expect("client compresses");
        let inflated = us.decompress(&compressed, true, usize::MAX).expect("server inflates");
        assert_eq!(&inflated[..], &payload[..]);
    }

    #[test]
    fn accept_response_still_rejects_own_compressor_below_supported() {
        // `client_max_window_bits` caps what *we* compress with, and zlib cannot
        // compress below 9, so this one must still be refused.
        let client = DeflateConfig::new();
        let response = PermessageDeflateConfig {
            client_max_window_bits: ClientMaxWindowBits::Bits(8.try_into().unwrap()),
            ..Default::default()
        };

        assert!(matches!(
            client.accept_response(response),
            Err(NegotiationError::UnsupportedClientMaxWindowBitsValue(8))
        ));
    }

    #[test]
    fn deflate_config_parse_params_accepts_quoted_values() {
        // A quoted value is legal per RFC 6455 §9.1. Rejecting it silently
        // declined compression as a server and failed a legal handshake as a
        // client, since both sides parse this value as an integer.
        assert_eq!(
            PermessageDeflateConfig::parse_params(
                WebsocketProtocolExtension::from_str(
                    "permessage-deflate; server_max_window_bits=\"10\"; client_max_window_bits=\"9\""
                )
                .unwrap()
                .params()
            ),
            Ok(PermessageDeflateConfig {
                server_max_window_bits: Some(10.try_into().unwrap()),
                client_max_window_bits: ClientMaxWindowBits::Bits(9.try_into().unwrap()),
                ..Default::default()
            })
        );
    }

    #[test]
    fn deflate_config_parse_params_valid() {
        assert_eq!(
            PermessageDeflateConfig::parse_params([]),
            Ok(PermessageDeflateConfig::default())
        );
        assert_eq!(
            PermessageDeflateConfig::parse_params(
                WebsocketProtocolExtension::from_str(
                    "permessage-deflate; client_max_window_bits=12; server_no_context_takeover"
                )
                .unwrap()
                .params()
            ),
            Ok(PermessageDeflateConfig {
                client_max_window_bits: ClientMaxWindowBits::Bits(12.try_into().unwrap()),
                server_no_context_takeover: true,
                ..Default::default()
            })
        );
    }

    #[test]
    fn deflate_rejects_a_valueless_server_max_window_bits() {
        // RFC 7692 §7.1.2.1 requires a value here, unlike
        // `client_max_window_bits` in §7.1.2.2, which may stand alone. The two
        // are asserted together because the asymmetry is the whole point: the
        // same shape is a rejection for one role and valid for the other.
        assert_eq!(
            PermessageDeflateConfig::parse_params([&WebsocketExtensionParam::new(
                "server_max_window_bits",
                None
            )]),
            // The absent value is reported as empty rather than as its own
            // variant; that is `InvalidParameterValue`'s existing shape.
            Err(ParameterError::InvalidParameterValue {
                name: "server_max_window_bits",
                value: String::new(),
            })
        );
        assert_eq!(
            PermessageDeflateConfig::parse_params([&WebsocketExtensionParam::new(
                "client_max_window_bits",
                None
            )])
            .map(|config| config.client_max_window_bits),
            Ok(ClientMaxWindowBits::NoValue)
        );
    }

    #[test]
    fn deflate_rejects_a_takeover_flag_carrying_a_value() {
        // RFC 7692 §7.1.1 gives these no value. Accepting one would mean
        // reading `server_no_context_takeover=0` as *enabling* the flag, which
        // is the opposite of what such a peer meant.
        for role in ["server", "client"] {
            let name = format!("{role}_no_context_takeover");
            assert_eq!(
                PermessageDeflateConfig::parse_params([&WebsocketExtensionParam::new(
                    name.clone(),
                    Some("0".to_string())
                )])
                .map_err(|e| e.to_string()),
                Err(format!("Invalid value 0 for parameter {name}")),
                "{name} must not accept a value"
            );
        }
        // Control: the same parameters without values are accepted.
        let config = PermessageDeflateConfig::parse_params([
            &WebsocketExtensionParam::new("server_no_context_takeover", None),
            &WebsocketExtensionParam::new("client_no_context_takeover", None),
        ])
        .expect("the valueless form is how these are meant to arrive");
        assert!(config.server_no_context_takeover && config.client_no_context_takeover);
    }

    #[test]
    fn deflate_rejects_unknown_parameters() {
        assert_eq!(
            PermessageDeflateConfig::parse_params([&WebsocketExtensionParam::new("unknown", None)]),
            Err(ParameterError::UnknownParameter("unknown".to_owned()))
        );
        assert_eq!(
            PermessageDeflateConfig::parse_params([
                &WebsocketExtensionParam::new("client_max_window_bits", Some("13".to_string())),
                &WebsocketExtensionParam::new("after-valid", None)
            ]),
            Err(ParameterError::UnknownParameter("after-valid".to_owned()))
        )
    }

    #[test]
    fn deflate_rejects_duplicate_parameters() {
        assert_eq!(
            PermessageDeflateConfig::parse_params(
                WebsocketProtocolExtension::from_str(
                    "permessage-deflate; client_max_window_bits=12; server_no_context_takeover; client_max_window_bits=12"
            ).unwrap().params()),
            Err(ParameterError::DuplicateParameter("client_max_window_bits".to_owned())),
        );
    }

    #[test]
    fn deflate_config_minimal_client_offer() {
        let client_config = DeflateConfig::new();

        let mut headers = Vec::with_capacity(1);
        SecWebsocketExtensions::new([client_config.as_offer().as_extension()]).encode(&mut headers);

        assert_eq!(
            headers,
            &[HeaderValue::from_static("permessage-deflate; client_max_window_bits")]
        )
    }

    #[test]
    fn deflate_server_respects_offer_server_no_context_takeover() {
        let server_cfg = DeflateConfig::default();

        let client_offer =
            PermessageDeflateConfig { server_no_context_takeover: true, ..Default::default() };

        assert_eq!(
            server_cfg.accept_offer(client_offer),
            Some((
                DeflateConfig { server_no_context_takeover: true, ..server_cfg },
                PermessageDeflateConfig { server_no_context_takeover: true, ..Default::default() }
            ))
        );
    }

    #[test]
    fn rejects_unsupported_client_max_window_bits_offer() {
        let server_config = DeflateConfig::new();

        // With the default value, the client should be able to say it will use
        // a smaller window size than the default.
        const SMALLER_WINDOW: NonZeroU8 = NonZeroU8::new(12).unwrap();
        assert_eq!(
            server_config.accept_offer(PermessageDeflateConfig {
                client_max_window_bits: ClientMaxWindowBits::Bits(SMALLER_WINDOW),
                ..Default::default()
            }),
            Some((
                DeflateConfig { client_max_window_bits: SMALLER_WINDOW, ..server_config },
                PermessageDeflateConfig {
                    client_max_window_bits: ClientMaxWindowBits::Bits(SMALLER_WINDOW),
                    ..Default::default()
                }
            ))
        );
    }

    #[test]
    fn interop() {
        // These are all mutually compatible, though they might result in
        // negotiated parameters that are not the default.
        const MODIFIERS: &[fn(DeflateConfig) -> DeflateConfig] = &[
            |config| config.set_no_context_takeover(Role::Client, true),
            |config| config.set_no_context_takeover(Role::Server, true),
            |config| config.set_max_window_bits(Role::Client, 12).unwrap(),
            |config| config.set_max_window_bits(Role::Server, 10).unwrap(),
        ];

        fn make_config(selector: u8) -> DeflateConfig {
            MODIFIERS
                .iter()
                .enumerate()
                .filter(|(i, _)| selector & (1 << i) != 0)
                .fold(DeflateConfig::new(), |config, (_, modifier)| modifier(config))
        }

        for client_selector in 0..(1 << MODIFIERS.len()) {
            let client_config = make_config(client_selector);
            for server_selector in 0..(1 << MODIFIERS.len()) {
                let server_config = make_config(server_selector);

                let offer = client_config.as_offer();
                let (_config, response) = server_config.accept_offer(offer).unzip();

                let response = response.unwrap_or_else(|| {
                    panic!("client: {client_config:?}, server: {server_config:?}, offer: {offer:?}")
                });

                let _accepted = client_config.accept_response(response).unwrap_or_else(|e|
                    panic!("client: {client_config:?}, server: {server_config:?}, offer: {offer:?}, response: {response:?}; error: {e}"));
            }
        }
    }

    #[test]
    fn rejects_unsupported_client_max_window_bits_response() {
        let client_config = DeflateConfig::new();

        assert_eq!(client_config.client_max_window_bits().get(), 15);
        // With the default value, the should be able to say it will use
        // a smaller window size than the default.
        const SMALLER_WINDOW: NonZeroU8 = NonZeroU8::new(12).unwrap();
        let server_response = PermessageDeflateConfig {
            server_max_window_bits: Some(*ALLOWED_WINDOW_BITS.end()),
            client_max_window_bits: ClientMaxWindowBits::Bits(SMALLER_WINDOW),
            ..Default::default()
        };

        assert_eq!(
            client_config.accept_response(server_response),
            Ok(DeflateConfig { client_max_window_bits: SMALLER_WINDOW, ..Default::default() })
        );

        // With a smaller allowed maximum window size, the same response will be rejected.
        let client_config =
            client_config.set_max_window_bits(Role::Client, SMALLER_WINDOW.get() - 1).unwrap();
        assert_eq!(
            client_config.accept_response(server_response),
            Err(NegotiationError::UnsupportedClientMaxWindowBitsValue(SMALLER_WINDOW.get()))
        );
    }

    mod rfc_7692_section_7_1_3_examples {
        use headers::HeaderMap;

        use super::*;

        #[track_caller]
        fn parse_extensions(raw: &[u8]) -> SecWebsocketExtensions {
            let headers: HeaderMap = {
                let mut hbuffer = [httparse::EMPTY_HEADER; 20];

                match httparse::parse_headers(raw, &mut hbuffer).unwrap() {
                    httparse::Status::Partial => panic!("preallocated buffer is too small"),
                    httparse::Status::Complete((_size, hdr)) => hdr
                        .iter()
                        .map(|h| {
                            (
                                http::HeaderName::from_bytes(h.name.as_bytes()).unwrap(),
                                HeaderValue::from_bytes(h.value).unwrap(),
                            )
                        })
                        .collect(),
                }
            };
            SecWebsocketExtensions::decode(
                &mut headers.get_all(SecWebsocketExtensions::name()).iter(),
            )
            .unwrap()
        }

        #[track_caller]
        fn parse_deflates(
            extensions: &SecWebsocketExtensions,
        ) -> impl Iterator<Item = PermessageDeflateConfig> + '_ {
            extensions
                .iter()
                .filter_map(|extension| {
                    (extension.name() == PER_MESSAGE_DEFLATE).then_some(extension.params())
                })
                .map(|params| PermessageDeflateConfig::parse_params(params).unwrap())
        }

        #[test]
        fn simplest() {
            // From RFC 7692 Section 7.1.3:
            //    The simplest "Sec-WebSocket-Extensions" header in a client's
            //    opening handshake to offer use of the "permessage-deflate"
            //    extension looks like this:
            let client_headers = parse_extensions(
                b"\
                Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            );
            let client_offers = parse_deflates(&client_headers);

            // ...
            //
            //    Since the "client_max_window_bits" extension parameter is not
            //    included in this extension negotiation offer, the server must
            //    not accept the offer with an extension negotiation response
            //    that includes the "client_max_window_bits" extension
            //    parameter.  The simplest "Sec- WebSocket-Extensions" header in
            //    a server's opening handshake to accept use of the
            //    "permessage-deflate" extension is the same
            let server_config = DeflateConfig::default();
            let (_server_config, accepted_offer) =
                client_offers.filter_map(|offer| server_config.accept_offer(offer)).next().unwrap();

            assert_eq!(SecWebsocketExtensions::new([accepted_offer.as_extension()]), client_headers)
        }

        #[test]
        fn client_multiple_offers() {
            // From RFC 7692 Section 7.1.3:
            //
            //   The following extension negotiation offer sent by a client is
            //   asking the server to use an LZ77 sliding window with a size of
            //   1,024 bytes or less and declaring that the client supports the
            //   "client_max_window_bits" extension parameter in an extension
            //   negotiation response.
            //
            // ...
            //
            //   This extension negotiation offer might be rejected by the
            //   server because the server doesn't support the
            //   "server_max_window_bits" extension parameter in an extension
            //   negotiation offer.  This is fine if the client cannot receive
            //   messages compressed using a larger sliding window size, but if
            //   the client just prefers using a small window but wants to fall
            //   back to the "permessage-deflate" without the
            //   "server_max_window_bits" extension parameter, the client can
            //   make an offer with the fallback option like this:
            let client_headers = parse_extensions(
                b"Sec-WebSocket-Extensions: \
                  permessage-deflate; \
                  client_max_window_bits; server_max_window_bits=10, \
                  permessage-deflate; \
                  client_max_window_bits\r\n\r\n",
            );

            let client_offers = parse_deflates(&client_headers);

            let server_config = DeflateConfig::default();
            let accepted_offers = client_offers
                .filter_map(|offer| server_config.accept_offer(offer))
                .map(|(_server_config, accepted)| {
                    SecWebsocketExtensions::new([accepted.as_extension()])
                })
                .collect::<Vec<_>>();
            // ...
            //
            //   The server can accept "permessage-deflate" by picking any
            //   supported one from the listed offers.  To accept the first
            //   option, for example, the server may send back a response as
            //   follows:
            assert_eq!(
                accepted_offers,
                [
                    parse_extensions(
                        b"Sec-WebSocket-Extensions: \
                    permessage-deflate; server_max_window_bits=10\r\n\r\n"
                    ),
                    // ...
                    //
                    //    To accept the second option, for example, the server may send
                    //    back a response as follows:
                    parse_extensions(b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
                ]
            );
        }
    }
}
