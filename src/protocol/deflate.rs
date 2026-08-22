use bytes::Bytes;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use http::{header::SEC_WEBSOCKET_EXTENSIONS, HeaderMap, HeaderValue};
use std::borrow::Cow;

use crate::{
    error::{Error, ProtocolError, Result},
    protocol::Role,
};

const NAME: &str = "permessage-deflate";

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Settings {
    pub(crate) compression: Compression,
    pub(crate) server_no_context_takeover: bool,
    pub(crate) client_no_context_takeover: bool,
    pub(crate) server_max_window_bits: u8,
    pub(crate) client_max_window_bits: u8,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            compression: Compression::default(),
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: 15,
            client_max_window_bits: 15,
        }
    }
}

impl Settings {
    pub(crate) fn max_window_bits(mut self, role: Role, bits: u8) -> Self {
        assert!((9..=15).contains(&bits), "deflate window bits must be in 9..=15");
        *match role {
            Role::Server => &mut self.server_max_window_bits,
            Role::Client => &mut self.client_max_window_bits,
        } = bits;
        self
    }

    pub(crate) fn no_context_takeover(mut self, role: Role, on: bool) -> Self {
        *match role {
            Role::Server => &mut self.server_no_context_takeover,
            Role::Client => &mut self.client_no_context_takeover,
        } = on;
        self
    }

    pub(crate) fn compression_level(mut self, level: u32) -> Self {
        assert!(level <= 9, "deflate compression level must be in 0..=9");
        self.compression = Compression::new(level);
        self
    }

    pub(crate) fn offer(self) -> HeaderValue {
        let mut value = String::from(NAME);
        if self.server_no_context_takeover {
            value.push_str("; server_no_context_takeover");
        }
        if self.client_no_context_takeover {
            value.push_str("; client_no_context_takeover");
        }
        if self.server_max_window_bits < 15 {
            value.push_str(&format!("; server_max_window_bits={}", self.server_max_window_bits));
        }
        if self.client_max_window_bits < 15 {
            value.push_str(&format!("; client_max_window_bits={}", self.client_max_window_bits));
        } else {
            value.push_str("; client_max_window_bits");
        }
        HeaderValue::from_str(&value).expect("the generated extension offer is valid")
    }

    pub(crate) fn accept_response(self, headers: &HeaderMap) -> Result<Option<Self>> {
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
        let Some(params) = selected else { return Ok(None) };
        if self.server_no_context_takeover && !params.server_no_context_takeover {
            return Err(invalid_header());
        }
        let mut agreed = self;
        agreed.server_no_context_takeover = params.server_no_context_takeover;
        agreed.client_no_context_takeover |= params.client_no_context_takeover;
        match params.server_max_window_bits {
            Some(bits) if bits > self.server_max_window_bits => return Err(invalid_header()),
            Some(bits) => agreed.server_max_window_bits = bits,
            None if self.server_max_window_bits < 15 => return Err(invalid_header()),
            None => {}
        }
        match params.client_max_window_bits {
            ClientWindow::NoValue => return Err(invalid_header()),
            ClientWindow::Bits(bits) if bits > self.client_max_window_bits || bits < 9 => {
                return Err(invalid_header());
            }
            ClientWindow::Bits(bits) => agreed.client_max_window_bits = bits,
            ClientWindow::Absent => {}
        }
        Ok(Some(agreed))
    }

    pub(crate) fn accept_offers(self, offers: &[HeaderValue]) -> Option<(Self, HeaderValue)> {
        for value in offers.iter().filter_map(|value| value.to_str().ok()) {
            for extension in split_quoted(value, b',').into_iter().flatten() {
                if let Ok(Some(offer)) = parse(extension) {
                    if let Some(accepted) = self.accept_offer(offer) {
                        return Some(accepted);
                    }
                }
            }
        }
        None
    }

    fn accept_offer(self, offer: Params) -> Option<(Self, HeaderValue)> {
        let mut agreed = self;
        agreed.server_no_context_takeover |= offer.server_no_context_takeover;
        agreed.client_no_context_takeover |= offer.client_no_context_takeover;

        let server_window = match offer.server_max_window_bits {
            Some(8) => return None,
            Some(bits) => Some(bits.min(self.server_max_window_bits)),
            None if self.server_max_window_bits < 15 => Some(self.server_max_window_bits),
            None => None,
        };
        if let Some(bits) = server_window {
            agreed.server_max_window_bits = bits;
        }

        let client_window = match offer.client_max_window_bits {
            ClientWindow::Absent if self.client_max_window_bits < 15 => return None,
            ClientWindow::Absent => None,
            ClientWindow::NoValue => Some(self.client_max_window_bits),
            ClientWindow::Bits(bits) => Some(bits.min(self.client_max_window_bits)),
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
}

#[derive(Debug)]
pub(crate) struct Context {
    encoder: Compress,
    decoder: Decompress,
    reset_encoder: bool,
    reset_decoder: bool,
}

impl Context {
    pub(crate) fn new(role: Role, settings: Settings) -> Self {
        let (own_window, peer_window, reset_encoder, reset_decoder) = match role {
            Role::Client => (
                settings.client_max_window_bits,
                settings.server_max_window_bits,
                settings.client_no_context_takeover,
                settings.server_no_context_takeover,
            ),
            Role::Server => (
                settings.server_max_window_bits,
                settings.client_max_window_bits,
                settings.server_no_context_takeover,
                settings.client_no_context_takeover,
            ),
        };
        Self {
            encoder: Compress::new_with_window_bits(settings.compression, false, own_window),
            decoder: Decompress::new_with_window_bits(false, peer_window.max(9)),
            reset_encoder,
            reset_decoder,
        }
    }

    pub(crate) fn reset_encoder(&mut self) {
        self.encoder.reset();
    }

    pub(crate) fn compress(&mut self, mut input: &[u8]) -> Result<Bytes> {
        const CHUNK: usize = 4096;
        const TRAILER: &[u8] = &[0, 0, 0xff, 0xff];
        if input.is_empty() {
            return Ok(Bytes::from_static(&[0]));
        }
        let mut output = Vec::new();
        while !input.is_empty() {
            output.reserve(CHUNK);
            let before = (self.encoder.total_in(), self.encoder.total_out());
            let status = self
                .encoder
                .compress_vec(input, &mut output, FlushCompress::None)
                .map_err(|_| ProtocolError::Compression)?;
            let consumed = (self.encoder.total_in() - before.0) as usize;
            let produced = (self.encoder.total_out() - before.1) as usize;
            input = &input[consumed..];
            if !progress(status, consumed, produced)? {
                break;
            }
        }
        loop {
            output.reserve(CHUNK);
            let before = self.encoder.total_out();
            let status = self
                .encoder
                .compress_vec(&[], &mut output, FlushCompress::Sync)
                .map_err(|_| ProtocolError::Compression)?;
            let produced = (self.encoder.total_out() - before) as usize;
            if !progress(status, 0, produced)? {
                break;
            }
        }
        if !output.ends_with(TRAILER) {
            self.encoder.reset();
            return Err(ProtocolError::Compression.into());
        }
        output.truncate(output.len() - TRAILER.len());
        if self.reset_encoder {
            self.encoder.reset();
        }
        Ok(output.into())
    }

    pub(crate) fn decompress(
        &mut self,
        input: &[u8],
        final_frame: bool,
        already: usize,
        max_size: Option<usize>,
    ) -> Result<Bytes> {
        const TRAILER: &[u8] = &[0, 0, 0xff, 0xff];
        let max_size = max_size.unwrap_or(usize::MAX);
        let mut output = Vec::new();
        self.inflate(input, already, max_size, &mut output)?;
        if final_frame {
            self.inflate(TRAILER, already, max_size, &mut output)?;
            if self.reset_decoder {
                self.decoder.reset(false);
            }
        }
        Ok(output.into())
    }

    fn inflate(
        &mut self,
        mut input: &[u8],
        already: usize,
        max_size: usize,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let mut scratch = [0; 4096];
        loop {
            let remaining = max_size.saturating_sub(already.saturating_add(output.len()));
            let writable = remaining.saturating_add(1).min(scratch.len());
            let before = (self.decoder.total_in(), self.decoder.total_out());
            let status = self
                .decoder
                .decompress(input, &mut scratch[..writable], FlushDecompress::None)
                .map_err(|_| ProtocolError::Compression)?;
            let consumed = (self.decoder.total_in() - before.0) as usize;
            let produced = (self.decoder.total_out() - before.1) as usize;
            output.extend_from_slice(&scratch[..produced]);
            if already.saturating_add(output.len()) > max_size {
                return Err(crate::error::CapacityError::MessageTooLong {
                    size: already.saturating_add(output.len()),
                    max_size,
                }
                .into());
            }
            input = &input[consumed..];
            if status == Status::StreamEnd {
                self.decoder.reset(false);
            }
            if !progress(status, consumed, produced)? {
                return Ok(());
            }
        }
    }
}

pub(crate) fn progress(status: Status, consumed: usize, produced: usize) -> Result<bool> {
    if consumed != 0 || produced != 0 {
        return Ok(true);
    }
    match status {
        Status::Ok => Err(ProtocolError::Compression.into()),
        Status::BufError | Status::StreamEnd => Ok(false),
    }
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

pub(crate) fn headers_select_deflate(headers: &HeaderMap) -> Result<bool> {
    for value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
        let value = value.to_str().map_err(|_| invalid_header())?;
        for extension in split_quoted(value, b',')? {
            let name = split_quoted(extension, b';')?.into_iter().next().unwrap_or("").trim();
            if name.eq_ignore_ascii_case(NAME) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod bounds {
    use super::*;
    use crate::error::{CapacityError, Error};

    fn pair() -> (Context, Context) {
        (
            Context::new(Role::Server, Settings::default()),
            Context::new(Role::Client, Settings::default()),
        )
    }

    /// `inflate` detects an over-budget message by allowing exactly one byte past
    /// the budget and observing that it arrived: `writable` is
    /// `remaining.saturating_add(1)`. That `+1` is the entire detector, so the
    /// interesting rows are the two either side of the boundary -- at the limit
    /// exactly, which must be accepted, and one byte over, which must not.
    #[test]
    fn a_message_is_accepted_at_the_limit_and_rejected_one_byte_over() {
        let payload = vec![b'x'; 4000];
        let (mut server, mut client) = pair();
        let wire = server.compress(&payload).expect("compress");

        let at_limit = client.decompress(&wire, true, 0, Some(payload.len()));
        assert_eq!(
            at_limit.expect("a message exactly at the limit must be accepted").as_ref(),
            &payload[..],
            "and it must decode whole"
        );

        let (mut server, mut client) = pair();
        let wire = server.compress(&payload).expect("compress");
        match client.decompress(&wire, true, 0, Some(payload.len() - 1)) {
            Err(Error::Capacity(CapacityError::MessageTooLong { size, max_size })) => {
                // `size > max_size` would be a tautology -- the error is only
                // constructed when that holds -- and echoing `max_size` back
                // asserts an input. The invariant with content is that detection
                // happens on the first byte past the budget.
                assert_eq!(size, max_size + 1, "detection must be one byte past the budget");
            }
            other => panic!("one byte over the limit must be MessageTooLong, got {other:?}"),
        }
    }

    /// `already` is the bytes an earlier frame of the same message contributed, so
    /// the budget is per message rather than per frame. Without it a fragmented
    /// message could deliver `max_size` bytes per frame indefinitely.
    #[test]
    fn the_budget_counts_bytes_delivered_by_earlier_frames() {
        let payload = vec![b'y'; 2000];
        let (mut server, mut client) = pair();
        let wire = server.compress(&payload).expect("compress");

        // Same message, same limit, but half of it is already accounted for.
        match client.decompress(&wire, true, 1500, Some(payload.len())) {
            Err(Error::Capacity(CapacityError::MessageTooLong { size, max_size })) => {
                // The reported size has to include the earlier frames' bytes, or
                // the budget is being applied per frame rather than per message.
                assert_eq!(size, max_size + 1, "`already` must be inside the reported size");
                assert!(size > 1500, "the earlier frame's 1500 bytes must be counted");
            }
            other => panic!("`already` must consume the budget, got {other:?}"),
        }
    }

    /// A highly compressible payload against a much smaller budget: the guard has
    /// to fire while inflating rather than after materialising everything.
    #[test]
    fn a_compression_bomb_is_stopped_rather_than_materialised() {
        let payload = vec![0u8; 512 * 1024];
        let (mut server, mut client) = pair();
        let wire = server.compress(&payload).expect("compress");
        assert!(wire.len() < 4096, "the fixture must actually be a bomb: {} bytes", wire.len());

        match client.decompress(&wire, true, 0, Some(8 * 1024)) {
            Err(Error::Capacity(CapacityError::MessageTooLong { size, max_size })) => {
                // `size` is the discriminator, not decoration. `writable` is
                // `remaining + 1`, so detection happens on the first byte past the
                // budget and the reported size is always exactly one over. Using
                // `max_size` instead of `remaining` would let a call produce a
                // whole 4 KiB scratch chunk before the check fires, and the same
                // variant would carry a size thousands of bytes larger. The public
                // error value is where per-call overshoot becomes observable.
                assert_eq!(
                    size,
                    max_size + 1,
                    "detection must happen one byte past the budget, not one chunk past it"
                );
            }
            other => panic!("a bomb against a small budget must be rejected, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod liveness {
    use super::*;

    /// `progress` is the only thing standing between a stalled codec and an
    /// unbounded loop, so every cell of its table is pinned. Zero progress with
    /// `Ok` is the stall: the backend claims success and consumed and produced
    /// nothing, so the caller would spin forever. `BufError`/`StreamEnd` with
    /// zero progress is ordinary termination.
    ///
    /// Deliberately a pure function rather than a driven loop: a mutant that
    /// removes the guard makes this row *fail*, where a loop-based test would
    /// hang and `cargo test` has no per-test timeout.
    #[test]
    fn zero_progress_on_ok_is_the_only_error_row() {
        for (status, consumed, produced, expected) in [
            (Status::Ok, 0, 0, None),
            (Status::Ok, 1, 0, Some(true)),
            (Status::Ok, 0, 1, Some(true)),
            (Status::BufError, 0, 0, Some(false)),
            (Status::BufError, 1, 0, Some(true)),
            (Status::StreamEnd, 0, 0, Some(false)),
            (Status::StreamEnd, 0, 1, Some(true)),
        ] {
            match (progress(status, consumed, produced), expected) {
                (Ok(got), Some(want)) => {
                    assert_eq!(got, want, "progress({status:?}, {consumed}, {produced})")
                }
                (Err(Error::Protocol(ProtocolError::Compression)), None) => {}
                (got, want) => panic!(
                    "progress({status:?}, {consumed}, {produced}) gave {got:?}, wanted {want:?}"
                ),
            }
        }
    }
}
