//! HTTP Request and response header handling.
use http::HeaderValue;
use thiserror::Error as ThisError;

/// A `Sec-WebSocket-Extensions` header value that does not parse.
///
/// Owned by this crate deliberately. The `headers::Header` implementation is the
/// other way to parse one, and its error type would oblige a caller to depend on
/// the `headers` crate to handle a parse failure — which is the whole reason
/// [`SecWebsocketExtensions::from_header_values`] exists.
///
/// [`SecWebsocketExtensions::from_header_values`]:
///     sec_websocket_extensions::SecWebsocketExtensions::from_header_values
#[derive(Copy, Clone, Debug, ThisError, PartialEq, Eq)]
#[error("malformed Sec-WebSocket-Extensions header")]
pub struct MalformedExtensionsHeader;

/// The `Sec-WebSocket-Extensions` header grammar.
pub mod sec_websocket_extensions;
pub use sec_websocket_extensions::{
    SecWebsocketExtensions, WebsocketExtensionParam, WebsocketProtocolExtension,
};

/// Reads a comma-delimited raw header into a Vec.
fn from_comma_delimited<'i, I, T, E>(values: &mut I) -> Result<E, MalformedExtensionsHeader>
where
    I: Iterator<Item = &'i HeaderValue>,
    T: ::std::str::FromStr,
    E: ::std::iter::FromIterator<T>,
{
    from_delimited(&mut values.flat_map(|header_value| header_value.to_str()), ',')
}

/// Reads a single-character-delimited raw header into a Vec.
fn from_delimited<'i, I, T, E>(
    values: &mut I,
    delimiter: char,
) -> Result<E, MalformedExtensionsHeader>
where
    I: Iterator<Item = &'i str>,
    T: ::std::str::FromStr,
    E: ::std::iter::FromIterator<T>,
{
    values
        .flat_map(|string| {
            let mut in_quotes = false;
            let mut escaped = false;
            string
                .split(move |c| {
                    if escaped {
                        // RFC 7230 quoted-pair: the character after a backslash
                        // is literal. Without this an escaped `"` closes the
                        // quoted-string, and a delimiter later in the same value
                        // splits it -- silently, on our own writer's output.
                        escaped = false;
                        false // dont split
                    } else if in_quotes {
                        match c {
                            '\\' => escaped = true,
                            '"' => in_quotes = false,
                            _ => {}
                        }
                        false // dont split
                    } else if c == delimiter {
                        true // split
                    } else {
                        if c == '"' {
                            in_quotes = true;
                        }
                        false // dont split
                    }
                })
                .filter_map(|x| match x.trim() {
                    "" => None,
                    y => Some(y),
                })
                .map(|x| x.parse().map_err(|_| MalformedExtensionsHeader))
        })
        .collect()
}
