use std::{borrow::Cow, fmt::Debug, iter::FromIterator, str::FromStr};

use bytes::BytesMut;
use http::HeaderValue;

use super::{from_comma_delimited, from_delimited, MalformedExtensionsHeader};

/// The `Sec-Websocket-Extensions` header.
///
/// This header is used in the Websocket handshake, sent by the client to the
/// server and then from the server to the client. It is a proposed and
/// agreed-upon list of websocket protocol extensions to use.
///
/// Parses and renders the grammar in RFC 6455 section 9.1: a comma-separated
/// list of extensions, each with semicolon-separated parameters whose values are
/// a `token` or a `quoted-string`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SecWebsocketExtensions(Vec<WebsocketProtocolExtension>);

/// An extension listed in a [`SecWebsocketExtensions`] header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WebsocketProtocolExtension {
    name: Cow<'static, str>,
    params: Vec<WebsocketExtensionParam>,
}

/// Named parameter for an extension in a `Sec-Websocket-Extensions` header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WebsocketExtensionParam {
    name: Cow<'static, str>,
    value: Option<String>,
}

impl SecWebsocketExtensions {
    /// Constructs a new header with the provided extensions.
    pub fn new(extensions: impl IntoIterator<Item = WebsocketProtocolExtension>) -> Self {
        Self(extensions.into_iter().collect())
    }

    /// Returns an iterator over the extensions in this header.
    pub fn iter(&self) -> <&Self as IntoIterator>::IntoIter {
        self.into_iter()
    }

    /// Parses the header from its raw values, joining list elements split
    /// across several header lines as RFC 7230 permits.
    ///
    /// This is the parse entry point for a caller that owns the HTTP handshake
    /// itself — a framework that has already read the request and needs to
    /// answer an extension offer. The [`headers::Header`] implementation does
    /// the same thing, but its error type would require depending on the
    /// `headers` crate merely to handle a malformed header.
    ///
    /// Quoting is respected: a parameter value may be a `quoted-string`
    /// containing `,` or `;` (RFC 6455 section 9.1), so the values must not be
    /// split before reaching here.
    pub fn from_header_values<'i, I>(values: I) -> Result<Self, MalformedExtensionsHeader>
    where
        I: IntoIterator<Item = &'i HeaderValue>,
    {
        from_comma_delimited(&mut values.into_iter()).map(Self)
    }

    /// Returns the number of extensions in this header.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns a [`HeaderValue`] with the encoded contents of this header.
    ///
    /// # Panics
    ///
    /// If any extension or parameter name is not an RFC 7230 `token`, or a
    /// parameter value contains bytes a header cannot carry. Quoting protects
    /// parameter *values* with separators in them, but names are always written
    /// bare, so a name containing `;` or `,` reparses as different structure.
    /// Construct from parsed input, or from names you control.
    pub fn header_value(&self) -> HeaderValue {
        let extensions = CommaDelimited(self.0.as_slice());
        let mut buffer = BytesMut::with_capacity(extensions.encoded_len());

        extensions.write_with(&mut |slice| buffer.extend_from_slice(slice));

        HeaderValue::from_maybe_shared(buffer).expect("valid construction")
    }
}

impl WebsocketProtocolExtension {
    /// Constructs a new extension directive with the given name and parameters.
    /// `name` must be an RFC 7230 `token`: it is written bare, so a name
    /// containing `;` or `,` reparses as different structure. Not checked here —
    /// see [`SecWebsocketExtensions::header_value`].
    pub fn new(
        name: impl Into<Cow<'static, str>>,
        params: impl IntoIterator<Item = WebsocketExtensionParam>,
    ) -> Self {
        Self { name: name.into(), params: params.into_iter().collect() }
    }

    /// The name of this extension directive.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns an iterator over the parameters for this extension directive.
    pub fn params(&self) -> impl Iterator<Item = &WebsocketExtensionParam> {
        self.params.iter()
    }
}

impl WebsocketExtensionParam {
    /// Constructs a new parameter with the given name and optional value.
    #[inline]
    /// `name` must be an RFC 7230 `token`; a value needing quotes is quoted on
    /// the way out. Neither is checked here — see
    /// [`SecWebsocketExtensions::header_value`].
    pub fn new(name: impl Into<Cow<'static, str>>, value: Option<String>) -> Self {
        Self { name: name.into(), value }
    }

    /// The name of the parameter.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The parameter value, if there is one.
    #[inline]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl headers::Header for SecWebsocketExtensions {
    fn name() -> &'static ::http::header::HeaderName {
        &::http::header::SEC_WEBSOCKET_EXTENSIONS
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        // One implementation: this exists to satisfy the `headers` trait, and
        // the parsing lives in the inherent method so the two cannot diverge.
        Self::from_header_values(values.by_ref()).map_err(|_| headers::Error::invalid())
    }
    fn encode<E: Extend<headers::HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(self.header_value()))
    }
}

impl From<WebsocketProtocolExtension> for SecWebsocketExtensions {
    fn from(value: WebsocketProtocolExtension) -> Self {
        Self(vec![value])
    }
}

impl FromIterator<WebsocketProtocolExtension> for SecWebsocketExtensions {
    fn from_iter<T: IntoIterator<Item = WebsocketProtocolExtension>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for SecWebsocketExtensions {
    type Item = WebsocketProtocolExtension;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a SecWebsocketExtensions {
    type Item = &'a WebsocketProtocolExtension;

    type IntoIter = std::slice::Iter<'a, WebsocketProtocolExtension>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl FromStr for WebsocketProtocolExtension {
    type Err = MalformedExtensionsHeader;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, tail) = s.split_once(';').map(|(n, t)| (n, Some(t))).unwrap_or((s, None));

        let params = from_delimited(&mut tail.into_iter(), ';')?;

        Ok(Self { name: name.trim().to_owned().into(), params })
    }
}

impl std::fmt::Display for WebsocketProtocolExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { name, params } = self;

        write!(f, "{name}")?;
        for param in params {
            write!(f, "; {param}")?;
        }

        Ok(())
    }
}

impl FromStr for WebsocketExtensionParam {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = s.split_once('=').map(|(n, t)| (n, Some(t))).unwrap_or((s, None));

        let value = value.map(|value| unquote(value.trim()));

        Ok(Self { name: name.trim().to_owned().into(), value })
    }
}

/// Undoes the `quoted-string` form RFC 6455 §9.1 allows for a param value.
///
/// Values reach consumers that parse them as integers, so a quoted value has to
/// arrive unquoted or it fails to parse — silently declining compression on the
/// server side and failing a legal handshake on the client side.
fn unquote(value: &str) -> String {
    let Some(inner) = value.strip_prefix('"').and_then(|value| value.strip_suffix('"')) else {
        return value.to_owned();
    };

    // The closing quote must not itself be escaped. `"10\"` is an unterminated
    // quoted-string rather than the value `10\`, so leave it as it arrived and
    // let it fail the integer parse every consumer applies, instead of quietly
    // turning it into something that parses as a different thing.
    let trailing_backslashes = inner.len() - inner.trim_end_matches('\\').len();
    if trailing_backslashes % 2 == 1 {
        return value.to_owned();
    }

    let mut unescaped = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        // A quoted-pair escapes the next character, whatever it is. The check
        // above leaves an even trailing run, so a `\` always has one to take.
        unescaped.push(if c == '\\' { chars.next().unwrap_or('\\') } else { c });
    }
    unescaped
}

/// Re-applies the `quoted-string` form when a value cannot be written bare.
///
/// RFC 6455 section 9.1 allows an extension parameter value to be a `token` or a
/// `quoted-string`. [`unquote`] accepts either, so without the mirror here a
/// value that arrived quoted is re-emitted bare — and one containing `;` or `,`
/// then reads as a parameter or extension boundary to the next parser, which is
/// structure loss rather than a formatting difference.
fn quote_if_needed(value: &str) -> std::borrow::Cow<'_, str> {
    // RFC 7230 `tchar`. Anything outside it, including an empty value, needs the
    // quoted form.
    let is_token = !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    if is_token {
        return std::borrow::Cow::Borrowed(value);
    }

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        if c == '"' || c == '\\' {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    std::borrow::Cow::Owned(quoted)
}

impl std::fmt::Display for WebsocketExtensionParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { name, value } = self;

        write!(f, "{name}")?;
        if let Some(value) = value {
            write!(f, "={}", quote_if_needed(value))?;
        }
        Ok(())
    }
}

trait WriteTo {
    fn encoded_len(&self) -> usize {
        let mut size = 0;
        self.write_with(&mut |slice| size += slice.len());
        size
    }

    fn write_with(&self, write: &mut (impl FnMut(&[u8]) + ?Sized));
}

impl WriteTo for WebsocketProtocolExtension {
    fn encoded_len(&self) -> usize {
        let Self { name, params } = self;

        let params_len: usize = params.iter().map(|p| p.encoded_len() + 2).sum();

        name.len() + params_len
    }

    fn write_with(&self, write: &mut (impl FnMut(&[u8]) + ?Sized)) {
        let Self { name, params } = self;
        write(name.as_bytes());

        for param in params {
            write(b"; ");
            param.write_with(write);
        }
    }
}

impl WriteTo for WebsocketExtensionParam {
    fn write_with(&self, write: &mut (impl FnMut(&[u8]) + ?Sized)) {
        let Self { name, value } = self;
        write(name.as_bytes());

        if let Some(value) = value {
            write(b"=");
            // This is the path `header_value` uses, so the quoting has to happen
            // here and not only in `Display`. `encoded_len` is derived from this
            // same walk, so the length follows the quoting automatically.
            write(quote_if_needed(value).as_bytes());
        }
    }
}

#[derive(Debug)]
struct CommaDelimited<T>(T);

impl<T> CommaDelimited<T> {
    const SEPARATOR: &[u8] = b", ";
}

impl<T: WriteTo> WriteTo for CommaDelimited<&[T]> {
    fn encoded_len(&self) -> usize {
        let all_encoded_len: usize = self.0.iter().map(T::encoded_len).sum();
        let all_separators_len = self.0.len().saturating_sub(1) * Self::SEPARATOR.len();
        all_encoded_len + all_separators_len
    }

    fn write_with(&self, write: &mut (impl FnMut(&[u8]) + ?Sized)) {
        let mut is_first = true;
        for item in self.0 {
            let was_first = std::mem::replace(&mut is_first, false);
            if !was_first {
                write(Self::SEPARATOR);
            }
            item.write_with(write);
        }
    }
}

impl<T: WriteTo, const N: usize> WriteTo for CommaDelimited<[T; N]> {
    fn encoded_len(&self) -> usize {
        CommaDelimited(self.0.as_slice()).encoded_len()
    }

    fn write_with(&self, write: &mut (impl FnMut(&[u8]) + ?Sized)) {
        CommaDelimited(self.0.as_slice()).write_with(write);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_param_value_needing_quotes_round_trips_through_the_header() {
        // Must go through the whole header, not a lone param: `FromStr` for a
        // single param splits only on the first `=`, so `x=a;b` round-trips at
        // that level either way. The loss happens where `;` and `,` are
        // structural -- which is the header. Testing the param alone passes with
        // the re-quote removed, which is how this test was wrong first.
        // `a"b,c` and `a"b;c` carry a separator *after* an escaped quote, which
        // is the only shape that reaches the splitter's escape handling: with
        // `with"quote` the value ends before any separator, so the bug hid here
        // for as long as this list did not contain both.
        for value in [
            r#"a;b"#,
            "a,b",
            "a b",
            "with\"quote",
            "back\\slash",
            "a\"b,c",
            "a\"b;c",
            "",
        ] {
            let original = SecWebsocketExtensions::new([WebsocketProtocolExtension::new(
                "permessage-deflate",
                [WebsocketExtensionParam::new("x", Some(value.to_owned()))],
            )]);

            let rendered = original.header_value();
            let reparsed = SecWebsocketExtensions::decode(&mut [rendered.clone()].iter())
                .unwrap_or_else(|e| panic!("our own header must parse: {rendered:?}: {e}"));

            assert_eq!(
                reparsed, original,
                "value {value:?} rendered as {rendered:?} and did not survive the header"
            );
        }
    }

    #[test]
    fn a_token_value_is_still_written_bare() {
        // The common case must not gain quotes: every consumer parses these as
        // integers and a quoted form would be a gratuitous wire change.
        let param = WebsocketExtensionParam::new("server_max_window_bits", Some("10".to_owned()));
        assert_eq!(param.to_string(), "server_max_window_bits=10");
    }

    use headers::{Header, HeaderMapExt as _};

    use super::*;

    fn test_decode<T: Header>(values: &[&str]) -> Option<T> {
        let mut map = ::http::HeaderMap::new();
        for val in values {
            map.append(T::name(), val.parse().unwrap());
        }
        map.typed_get()
    }

    #[cfg(test)]
    fn test_encode<T: Header>(header: T) -> ::http::HeaderMap {
        let mut map = ::http::HeaderMap::new();
        map.typed_insert(header);
        map
    }

    #[test]
    fn parse_quoted_param_value() {
        // RFC 6455 §9.1 gives extension param values as `token | quoted-string`,
        // so a quoted value is legal on the wire and must reach the consumer
        // unquoted or it will not parse as an integer.
        let extensions = test_decode::<SecWebsocketExtensions>(&[
            "permessage-deflate; server_max_window_bits=\"10\"",
        ])
        .expect("valid");

        let param = &extensions.0[0].params().next().expect("a param");
        assert_eq!(param.name(), "server_max_window_bits");
        assert_eq!(param.value(), Some("10"));
    }

    #[test]
    fn parse_quoted_param_value_with_escapes() {
        // A quoted-pair is unescaped; a backslash escaping the *closing* quote
        // leaves the string unterminated, so the value is left as it arrived
        // rather than becoming `10\`, which would parse as a different thing.
        for (wire, expected) in
            [(r#"a; p="1\0""#, r#"10"#), (r#"a; p="1\\""#, r#"1\"#), (r#"a; p="10\""#, r#""10\""#)]
        {
            let extensions = test_decode::<SecWebsocketExtensions>(&[wire]).expect("valid");
            let param = extensions.0[0].params().next().expect("a param");
            assert_eq!(param.value(), Some(expected), "wire: {wire}");
        }
    }

    #[test]
    fn parse_separate_headers() {
        // From https://tools.ietf.org/html/rfc6455#section-9.1
        let extensions =
            test_decode::<SecWebsocketExtensions>(&["foo", "bar; baz=2"]).expect("valid");

        assert_eq!(
            extensions,
            SecWebsocketExtensions(vec![
                WebsocketProtocolExtension { name: "foo".into(), params: vec![] },
                WebsocketProtocolExtension {
                    name: "bar".into(),
                    params: vec![WebsocketExtensionParam {
                        name: "baz".into(),
                        value: Some("2".to_owned())
                    }],
                }
            ])
        );
    }

    #[test]
    fn round_trip_complex() {
        let extensions = test_decode::<SecWebsocketExtensions>(&[
            "deflate-stream",
            "mux; max-channels=4; flow-control, deflate-stream",
            "private-extension",
        ])
        .expect("valid");

        let headers = test_encode(extensions);
        assert_eq!(
            headers["sec-websocket-extensions"],
            "deflate-stream, mux; max-channels=4; flow-control, deflate-stream, private-extension"
        );
    }

    #[test]
    fn write_to_exact_encoded_len() {
        trait WriteToDyn: Debug {
            fn encoded_len(&self) -> usize;
            fn write_with(&self, write: &mut dyn FnMut(&[u8]));
        }

        impl<W: WriteTo + Debug> WriteToDyn for W {
            fn encoded_len(&self) -> usize {
                WriteTo::encoded_len(self)
            }

            fn write_with(&self, write: &mut dyn FnMut(&[u8])) {
                WriteTo::write_with(self, write);
            }
        }

        // This isn't a required property for correctness but if the length
        // precomputation is wrong we'll over- or under-allocate during
        // conversion.
        let cases: &[Box<dyn WriteToDyn>] = &[
            Box::new(CommaDelimited([
                WebsocketProtocolExtension::from_str("extension-name").unwrap(),
                WebsocketProtocolExtension::from_str("with-params; a=5; b=8").unwrap(),
            ])),
            Box::new(CommaDelimited::<[WebsocketProtocolExtension; 0]>([])),
            Box::new(CommaDelimited([
                WebsocketProtocolExtension::from_str("duplicate-name").unwrap(),
                WebsocketProtocolExtension::from_str("duplicate-name").unwrap(),
                WebsocketProtocolExtension::from_str("duplicate-name").unwrap(),
            ])),
            Box::new(WebsocketProtocolExtension::new(
                "name",
                ["foo=123".parse().unwrap(), "bar".parse().unwrap(), "baz=four".parse().unwrap()],
            )),
        ];

        for case in cases {
            let mut value = Vec::new();
            let expected_len = case.encoded_len();
            case.write_with(&mut |slice| value.extend_from_slice(slice));

            assert_eq!(value.len(), expected_len, "for {case:?}");
        }
    }
}
