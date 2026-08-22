use std::borrow::Cow;

use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};

use super::{Settings, NAME};
use crate::error::{Error, ProtocolError, Result};

pub(super) fn offer(settings: Settings) -> HeaderValue {
    let mut value = String::from(NAME);
    if settings.server_no_context_takeover {
        value.push_str("; server_no_context_takeover");
    }
    if settings.client_no_context_takeover {
        value.push_str("; client_no_context_takeover");
    }
    if settings.server_max_window_bits < 15 {
        value.push_str(&format!("; server_max_window_bits={}", settings.server_max_window_bits));
    }
    if settings.client_max_window_bits < 15 {
        value.push_str(&format!("; client_max_window_bits={}", settings.client_max_window_bits));
    } else {
        value.push_str("; client_max_window_bits");
    }
    HeaderValue::from_str(&value).expect("the generated extension offer is valid")
}

pub(super) fn accept_response(settings: Settings, headers: &HeaderMap) -> Result<Option<Settings>> {
    let mut selected = None;
    for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
        let value = value.to_str().map_err(|_| invalid_header())?;
        for extension in split_quoted(value, b',')? {
            if let Some(params) = parse(extension)? {
                if selected.replace(params).is_some() {
                    return Err(invalid_header());
                }
            }
        }
    }
    let Some(params) = selected else {
        return Ok(None);
    };
    if settings.server_no_context_takeover && !params.server_no_context_takeover {
        return Err(invalid_header());
    }
    let mut agreed = settings;
    agreed.server_no_context_takeover = params.server_no_context_takeover;
    agreed.client_no_context_takeover |= params.client_no_context_takeover;
    match params.server_max_window_bits {
        Some(bits) if bits > settings.server_max_window_bits => return Err(invalid_header()),
        Some(bits) => agreed.server_max_window_bits = bits,
        None if settings.server_max_window_bits < 15 => return Err(invalid_header()),
        None => {}
    }
    match params.client_max_window_bits {
        ClientWindow::NoValue => return Err(invalid_header()),
        ClientWindow::Bits(bits) if bits > settings.client_max_window_bits || bits < 9 => {
            return Err(invalid_header());
        }
        ClientWindow::Bits(bits) => agreed.client_max_window_bits = bits,
        ClientWindow::Absent => {}
    }
    Ok(Some(agreed))
}

pub(super) fn accept_offers(
    settings: Settings,
    offers: &[HeaderValue],
) -> Option<(Settings, HeaderValue)> {
    for value in offers.iter().filter_map(|value| value.to_str().ok()) {
        for extension in split_quoted(value, b',').into_iter().flatten() {
            if let Ok(Some(offer)) = parse(extension) {
                if let Some(accepted) = accept_offer(settings, offer) {
                    return Some(accepted);
                }
            }
        }
    }
    None
}

fn accept_offer(settings: Settings, offer: Params) -> Option<(Settings, HeaderValue)> {
    let mut agreed = settings;
    agreed.server_no_context_takeover |= offer.server_no_context_takeover;
    agreed.client_no_context_takeover |= offer.client_no_context_takeover;

    let server_window = match offer.server_max_window_bits {
        Some(8) => return None,
        Some(bits) => Some(bits.min(settings.server_max_window_bits)),
        None if settings.server_max_window_bits < 15 => Some(settings.server_max_window_bits),
        None => None,
    };
    if let Some(bits) = server_window {
        agreed.server_max_window_bits = bits;
    }

    let client_window = match offer.client_max_window_bits {
        ClientWindow::Absent if settings.client_max_window_bits < 15 => return None,
        ClientWindow::Absent => None,
        ClientWindow::NoValue => Some(settings.client_max_window_bits),
        ClientWindow::Bits(bits) => Some(bits.min(settings.client_max_window_bits)),
    };
    if let Some(bits) = client_window {
        agreed.client_max_window_bits = bits;
    }

    let mut response = String::from(NAME);
    if agreed.server_no_context_takeover {
        response.push_str("; server_no_context_takeover");
    }
    if agreed.client_no_context_takeover {
        response.push_str("; client_no_context_takeover");
    }
    if let Some(bits) = server_window {
        response.push_str(&format!("; server_max_window_bits={bits}"));
    }
    if let Some(bits) = client_window.filter(|bits| *bits < 15) {
        response.push_str(&format!("; client_max_window_bits={bits}"));
    }
    Some((agreed, HeaderValue::from_str(&response).expect("generated response is valid")))
}

#[derive(Default)]
struct Params {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: Option<u8>,
    client_max_window_bits: ClientWindow,
    seen: u8,
}

#[derive(Default)]
enum ClientWindow {
    #[default]
    Absent,
    NoValue,
    Bits(u8),
}

fn parse(extension: &str) -> Result<Option<Params>> {
    let parts = split_quoted(extension, b';')?;
    let name = parts.first().map_or("", |name| name.trim());
    if name.is_empty() {
        return if extension.trim().is_empty() { Ok(None) } else { Err(invalid_header()) };
    }
    // HTTP field values use case-insensitive tokens; accept that leniency for
    // extension and parameter names while keeping parameter values exact.
    if !name.eq_ignore_ascii_case(NAME) {
        return Ok(None);
    }
    let mut parsed = Params::default();
    for parameter in &parts[1..] {
        let (name, value) = parameter
            .trim()
            .split_once('=')
            .map_or((parameter.trim(), None), |(name, value)| (name.trim(), Some(value.trim())));
        let bit = if name.eq_ignore_ascii_case("server_no_context_takeover") {
            1
        } else if name.eq_ignore_ascii_case("client_no_context_takeover") {
            2
        } else if name.eq_ignore_ascii_case("server_max_window_bits") {
            4
        } else if name.eq_ignore_ascii_case("client_max_window_bits") {
            8
        } else {
            return Err(invalid_header());
        };
        if parsed.seen & bit != 0 {
            return Err(invalid_header());
        }
        parsed.seen |= bit;
        match bit {
            1 if value.is_none() => parsed.server_no_context_takeover = true,
            2 if value.is_none() => parsed.client_no_context_takeover = true,
            4 => {
                parsed.server_max_window_bits = Some(parse_bits(value.ok_or_else(invalid_header)?)?)
            }
            8 => {
                parsed.client_max_window_bits = match value {
                    Some(value) => ClientWindow::Bits(parse_bits(value)?),
                    None => ClientWindow::NoValue,
                }
            }
            _ => return Err(invalid_header()),
        }
    }
    Ok(Some(parsed))
}

fn parse_bits(value: &str) -> Result<u8> {
    let value = unquote(value)?;
    if !value.bytes().all(|byte| byte.is_ascii_digit()) || value.len() > 1 && value.starts_with('0')
    {
        return Err(invalid_header());
    }
    value.parse::<u8>().ok().filter(|bits| (8..=15).contains(bits)).ok_or_else(invalid_header)
}

fn split_quoted(value: &str, delimiter: u8) -> Result<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == delimiter {
            parts.push(&value[start..index]);
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(invalid_header());
    }
    parts.push(&value[start..]);
    Ok(parts)
}

fn unquote(value: &str) -> Result<Cow<'_, str>> {
    if !value.starts_with('"') {
        return if value.contains('"') { Err(invalid_header()) } else { Ok(Cow::Borrowed(value)) };
    }
    let mut output = String::new();
    let mut chars = value[1..].chars();
    while let Some(character) = chars.next() {
        match character {
            '\\' => output.push(chars.next().ok_or_else(invalid_header)?),
            '"' if chars.next().is_none() => return Ok(Cow::Owned(output)),
            '"' => return Err(invalid_header()),
            character => output.push(character),
        }
    }
    Err(invalid_header())
}

fn invalid_header() -> Error {
    ProtocolError::InvalidHeader(SEC_WEBSOCKET_EXTENSIONS.clone().into()).into()
}

pub(crate) fn headers_select_deflate(headers: &HeaderMap) -> bool {
    for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
        let Ok(value) = value.to_str() else { continue };
        let mut start = 0;
        let mut quoted = false;
        let mut escaped = false;
        for (index, byte) in value.bytes().enumerate() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
            } else if byte == b'"' {
                quoted = true;
            } else if byte == b',' {
                if extension_is_deflate(&value[start..index]) {
                    return true;
                }
                start = index + 1;
            }
        }
        if extension_is_deflate(&value[start..]) {
            return true;
        }
    }
    false
}

fn extension_is_deflate(extension: &str) -> bool {
    extension.split_once(';').map_or(extension, |(name, _)| name).trim().eq_ignore_ascii_case(NAME)
}
