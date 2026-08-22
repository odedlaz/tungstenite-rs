//! Implements "permessage-deflate" PMCE defined in [RFC 7692 Section 7]
//!
//! [RFC 7692 Section 7]: https://tools.ietf.org/html/rfc7692#section-7
use std::cmp::min;

use bytes::Bytes;
use flate2::{Compress, Decompress, FlushCompress, FlushDecompress, Status};
use thiserror::Error;

use crate::{extensions::compression::DecompressionError, protocol::Role};

mod config;
#[cfg_attr(not(feature = "handshake"), allow(unused_imports))]
pub use config::ParameterError as DeflateParameterError;
pub use config::{
    DeflateConfig, NegotiationError as DeflateNegotiationError, PermessageDeflateConfig,
    PER_MESSAGE_DEFLATE as EXTENSION_NAME, SUPPORTED_WINDOW_BITS,
};

#[derive(Debug)]
/// Manages per message compression using DEFLATE.
pub struct DeflateContext {
    compress: DeflateCompress,
    decompress: DeflateDecompress,
}

/// Errors from `permessage-deflate` extension.
#[derive(Copy, Clone, Debug, Error, PartialEq, Eq)]
pub enum DeflateError {
    /// Compress failed
    #[error("Failed to compress")]
    Compress,
    /// Decompress failed
    #[error("Failed to decompress")]
    Decompress,
}

#[derive(Debug)]
struct DeflateCompress {
    own_context_takeover: bool,
    /// The actual compressor to run payloads through.
    ///
    /// Use the low-level [`Compress`] API instead of the higher-level
    /// [`flate2::zlib::write::ZlibEncoder`] so we can compress directly into
    /// the output buffer instead of the intermediate one that that type holds.
    compressor: Compress,
}

#[derive(Debug)]
struct DeflateDecompress {
    /// The actual decompressor to run payloads through.
    ///
    /// Use the low-level [`Decompress`] API instead of the higher-level
    /// [`flate2::zlib::write::ZlibDecoder`] so we can decompress directly into
    /// the output buffer instead of the intermediate one that that type holds.
    /// This also lets us avoid some decompression errors that the higher-level
    /// version exhibited with certain highly-compressed payloads.
    decompressor: Decompress,
    peer_context_takeover: bool,
}

impl DeflateContext {
    pub(crate) fn new(role: Role, config: DeflateConfig) -> Self {
        let DeflateConfig {
            server_no_context_takeover,
            client_no_context_takeover,
            compression,
            ..
        } = config;

        // The `client_`/`server_` parameters are per direction, so each side
        // reads its own prefix for compression and the peer's for
        // decompression (RFC 7692 §7). `role` below is our own end.
        let (own_no_context_takeover, peer_no_context_takeover) = match role {
            Role::Client => (client_no_context_takeover, server_no_context_takeover),
            Role::Server => (server_no_context_takeover, client_no_context_takeover),
        };

        // Both ends of the connection act as both compressor and decompressor.
        // We compress with the window size for our role and decompress with the
        // size for the opposite role.
        let (compressor_window_bits, decompressor_window_bits) = match role {
            Role::Client => (config.client_max_window_bits(), config.server_max_window_bits()),
            Role::Server => (config.server_max_window_bits(), config.client_max_window_bits()),
        };

        DeflateContext {
            compress: DeflateCompress {
                own_context_takeover: !own_no_context_takeover,
                compressor: Compress::new_with_window_bits(
                    compression,
                    false,
                    compressor_window_bits.get(),
                ),
            },
            decompress: DeflateDecompress {
                peer_context_takeover: !peer_no_context_takeover,
                // A peer may legally compress with an 8-bit window, which
                // `Decompress::new_with_window_bits` panics on. Inflating with a
                // larger window than the sender used is always correct, so raise
                // it to the smallest flate2 accepts.
                decompressor: Decompress::new_with_window_bits(
                    false,
                    decompressor_window_bits.get().max(SUPPORTED_WINDOW_BITS.start().get()),
                ),
            },
        }
    }

    /// Compress the payload of an outgoing message.
    pub(crate) fn compress(&mut self, data: &[u8]) -> Result<Bytes, DeflateError> {
        self.compress.compress(data).map_err(|e| {
            log::debug!("compression failed: {e}");
            DeflateError::Compress
        })
    }

    /// Decompress the payload in a received frame.
    ///
    /// The `is_final` argument should only be set when calling with the contents of the last frame in a message.
    pub(crate) fn decompress(
        &mut self,
        data: &[u8],
        is_final: bool,
        size_limit: usize,
    ) -> Result<Bytes, DecompressionError<DeflateError>> {
        self.decompress.decompress(data, is_final, size_limit).map_err(|e| {
            e.map(|e: std::io::Error| {
                log::debug!("decompression failed: {e}");
                DeflateError::Decompress
            })
        })
    }
}

const ELIDED_TRAILER_BLOCK_CONTENTS: &[u8] = &[0x00, 0x00, 0xff, 0xff];

impl DeflateCompress {
    /// Compress the contents of an entire message.
    ///
    /// This is asymmetric with [`DeflateDecompress::decompress`] in that it
    /// operates on the contents of an entire message, not the comprising frames.
    fn compress(&mut self, mut data: &[u8]) -> Result<Bytes, std::io::Error> {
        log::trace!("compressing message payload with {} bytes", data.len());
        if data.is_empty() {
            // Fast path for an empty payload: it gets DEFLATE compressed to a
            // zero-length uncompressed block, which conveniently is
            // concat([0x00], ELIDED_TRAILER_BLOCK_CONTENTS). Then, per the RFC,
            // we elide the trailing 4 bytes to get a single 0x00 byte as the
            // compressed payload.
            return Ok(Bytes::from_static(&[0x00]));
        }

        let mut output = Vec::new();

        // The amount of space that should be available in `output` before
        // attempting to compress data into it.
        const REQUIRED_OUTPUT_SPACE: usize = 4096;

        {
            let mut total_read = self.compressor.total_in();
            loop {
                // Make sure there's space for compress_vec to write to.
                output.reserve(REQUIRED_OUTPUT_SPACE);

                let r = self.compressor.compress_vec(data, &mut output, FlushCompress::None)?;

                let read_before = std::mem::replace(&mut total_read, self.compressor.total_in());
                let read = (total_read - read_before) as usize;

                data = &data[read..];
                log::trace!(
                    "compressed {read} bytes, {} remaining; partial output is {} bytes",
                    data.len(),
                    output.len()
                );

                match r {
                    Status::Ok => continue,
                    Status::BufError if read == 0 => {
                        // We made no progress, so this BufError means that
                        // we're out of input.
                        break;
                    }
                    Status::BufError => {
                        // We made some progress, so we can continue after
                        // making more output space.
                        continue;
                    }
                    Status::StreamEnd => break,
                }
            }
        }

        log::trace!("flushing compressed data");

        // RFC 7692 §7.2.1 step 2 wants the payload to end with an empty
        // uncompressed block, which step 3 then truncates off. One
        // `compress_vec` with an empty slice ought to emit it — it is
        // documented to write "as much output as possible" — but some backends
        // return `Ok` as soon as *any* output is written, so loop until it
        // stops making progress. The loop can go once that contradiction is
        // fixed:
        // - https://github.com/Frommi/miniz_oxide/issues/105
        // - https://github.com/rust-lang/flate2-rs/blob/1.1.2/src/ffi/rust.rs#L169
        // - https://github.com/Frommi/miniz_oxide/blob/0.8.8/miniz_oxide/src/deflate/stream.rs#L82
        {
            let mut total_out = self.compressor.total_out();
            loop {
                output.reserve(REQUIRED_OUTPUT_SPACE);
                let output_len_before = output.len();
                let output_available_before = output.capacity() - output_len_before;

                let _ = self.compressor.compress_vec(&[], &mut output, FlushCompress::Sync)?;
                log::trace!(
                    "flushed {} bytes into an available {output_available_before} bytes",
                    output.len() - output_len_before,
                );
                let out_before = std::mem::replace(&mut total_out, self.compressor.total_out());
                if total_out == out_before {
                    break;
                }
            }
        }

        // RFC 7692 §7.2.1 step 3: remove the trailing 0x00 0x00 0xff 0xff, so
        // the last octet holds DEFLATE header bits with BTYPE set to 00.

        debug_assert!(output.ends_with(ELIDED_TRAILER_BLOCK_CONTENTS), "output is {output:02x?}");
        output.truncate(output.len() - ELIDED_TRAILER_BLOCK_CONTENTS.len());

        if !self.own_context_takeover {
            // Reset if the next frame isn't supposed to be starting with the
            // same compression window.
            self.compressor.reset();
        }

        log::trace!("finished compression into {} bytes", output.len());
        Ok(Bytes::from(output))
    }
}

impl DeflateDecompress {
    /// Decompress the contents of a single frame.
    ///
    /// The `is_final` argument must be `true` if and only if the frame is the
    /// last one in a message. The `size_limit` argument is the maximum number
    /// of bytes that can be decompressed. If the input `data` decompresses to
    /// more than `size_limit` bytes, [`DecompressionError::SizeLimitReached`]
    /// will be returned.
    fn decompress(
        &mut self,
        data: &[u8],
        is_final: bool,
        size_limit: usize,
    ) -> Result<Bytes, DecompressionError<std::io::Error>> {
        // RFC 7692 §7.2.2: append 0x00 0x00 0xff 0xff — the empty block the
        // sender truncated — then inflate.

        let mut output = Vec::new();

        log::trace!(
            "decompressing {} bytes in {} frame",
            data.len(),
            if is_final { "final" } else { "intermediate" }
        );
        let mut total_read = self.decompressor.total_in();

        let mut decompress_from = |mut data: &[u8]| {
            loop {
                // Make sure there's some space to decompress into,
                // optimistically assuming a 50% compression ratio of the input,
                // but never reserve past the budget. The guess is keyed to the
                // input, so an operator who lowers `max_message_size` to bound
                // memory would still admit up to `2 * max_frame_size` of
                // decompressed bytes in a single call before the check below
                // runs. One byte past the budget is all that check needs.
                let headroom = size_limit.saturating_sub(output.len()).saturating_add(1);
                output.reserve(min(2 * data.len(), headroom));

                let r =
                    self.decompressor.decompress_vec(data, &mut output, FlushDecompress::None)?;

                if output.len() > size_limit {
                    return Err(DecompressionError::SizeLimitReached);
                }
                let read_before = std::mem::replace(&mut total_read, self.decompressor.total_in());

                let read = (total_read - read_before) as usize;

                data = &data[read..];

                match r {
                    Status::Ok => continue,
                    Status::BufError => {
                        // We've either run out of input data or output space.
                        // While input is pending the cap still leaves at
                        // least one spare byte, which is enough for
                        // `decompress_vec` to make progress and push `len`
                        // past the limit, erroring above rather than arriving
                        // here. The empty-input iteration reserves nothing,
                        // and that is the out-of-input case this arm is for.
                        break;
                    }
                    Status::StreamEnd => {
                        // A peer without an empty-block flush may set BFINAL
                        // instead (RFC 7692 §7.2.3.4). `reset` discards the
                        // whole sliding window, which is only safe if the peer
                        // set BFINAL by telling its own compressor the stream
                        // was ending — resetting its window too — so nothing
                        // later back-references this block or any before it. A
                        // peer that sets BFINAL some other way breaks that, but
                        // this matches other deployed implementations.
                        self.decompressor.reset(false);
                        total_read = 0;
                    }
                }
            }
            Ok(())
        };

        decompress_from(data)?;

        if is_final {
            // Decompress the final block that is part of the logical input to
            // DEFLATE but is elided from the message payloads. This implicitly
            // flushes out any pending bytes that were part of the previous
            // block and doesn't leave any others since the trailer is explicitly
            // an empty block.
            decompress_from(ELIDED_TRAILER_BLOCK_CONTENTS)?;

            if !self.peer_context_takeover {
                self.decompressor.reset(false);
            }
        }

        Ok(Bytes::from(output))
    }
}

#[cfg(test)]
mod context_takeover_asymmetry {
    use super::*;

    // `server_no_context_takeover` drives two different resets: the server's own
    // compressor, and the client's decompressor for that direction. Giving two
    // contexts opposite values for that one field is therefore the only way to
    // build a compressor/decompressor pair that disagrees about history -- which
    // is the state a reset-after-rejected-write would leave a connection in.
    fn pair(encoder_resets: bool, decoder_resets: bool) -> (DeflateContext, DeflateContext) {
        let cfg = |v| DeflateConfig::default().set_no_context_takeover(Role::Server, v);
        (
            DeflateContext::new(Role::Server, cfg(encoder_resets)),
            DeflateContext::new(Role::Client, cfg(decoder_resets)),
        )
    }

    const REPEATED: &[u8] = b"the quick brown fox jumps over the lazy dog, at length";
    const UNRELATED: &[u8] = b"a wholly different payload sharing no prefix, xyzzy";

    /// An encoder that resets stays decodable by a peer that keeps history.
    ///
    /// This is the property that decides whether resetting after a rejected
    /// write repairs the dropped-message case: the encoder starts from an empty
    /// window, so it cannot reference the message the peer never received.
    #[test]
    fn resetting_encoder_stays_decodable_by_a_peer_keeping_history() {
        let (mut encoder, mut decoder) = pair(true, false);

        for (i, payload) in [REPEATED, REPEATED, REPEATED, UNRELATED].iter().enumerate() {
            let wire = encoder.compress(payload).expect("compress");
            let out = decoder
                .decompress(&wire, true, usize::MAX)
                .unwrap_or_else(|e| panic!("message {i} failed to decode: {e:?}"));
            assert_eq!(out.as_ref(), *payload, "message {i} round-trip");
        }
    }

    /// The control, and the test above is vacuous without it: the same harness
    /// must be able to *observe* a desync, or a pass proves only that it cannot
    /// see one. Reversing the asymmetry breaks decoding from the second message
    /// -- the first still succeeds because there is no history to lose yet.
    #[test]
    fn control_resetting_decoder_desyncs_against_an_encoder_keeping_history() {
        let (mut encoder, mut decoder) = pair(false, true);

        let first = encoder.compress(REPEATED).expect("compress");
        assert_eq!(
            decoder.decompress(&first, true, usize::MAX).expect("first decodes").as_ref(),
            REPEATED,
            "the first message has no prior history to depend on"
        );

        let second = encoder.compress(REPEATED).expect("compress");
        assert!(
            decoder.decompress(&second, true, usize::MAX).is_err(),
            "a decoder that discarded its window must fail on history-referencing input"
        );
    }
}

#[cfg(test)]
pub(crate) mod test {
    use rand::{distr::Distribution as _, Rng as _, SeedableRng as _};

    use super::*;

    #[test]
    fn interop() {
        let mut data = vec![0; 2048];
        rand::rngs::SmallRng::seed_from_u64(1023).fill_bytes(&mut data);

        let configs = [
            DeflateConfig::default(),
            DeflateConfig::default().set_no_context_takeover(Role::Client, true),
            DeflateConfig::default()
                .set_no_context_takeover(Role::Client, true)
                .set_max_window_bits(Role::Client, 10)
                .unwrap(),
            DeflateConfig::default().set_max_window_bits(Role::Client, 10).unwrap(),
        ];

        let frame_sizes = [16, 64, data.len()];

        for config in configs {
            for frame_size in frame_sizes {
                let mut client = DeflateContext::new(Role::Client, config);
                let mut server = DeflateContext::new(Role::Server, config);

                let mut send_and_receive = |data| {
                    let compressed = client.compress(data).unwrap();

                    let mut decompressed = Vec::<u8>::new();

                    let mut it = compressed.chunks(frame_size).peekable();
                    while let Some(frame) = it.next() {
                        decompressed.extend_from_slice(
                            &server.decompress(frame, it.peek().is_none(), usize::MAX).unwrap(),
                        );
                    }
                    decompressed
                };

                let decompressed = send_and_receive(&data);
                assert_eq!(data, decompressed);

                // Make sure we haven't broken compression or decompression for
                // the *next* message.
                let decompressed = send_and_receive(b"second message");
                assert_eq!(decompressed, b"second message");
            }
        }
    }

    #[test]
    fn large_message_compression() {
        let mut data = vec![0; 1 << 19];
        rand::rngs::SmallRng::seed_from_u64(1023).fill_bytes(&mut data);

        let mut context = DeflateContext::new(Role::Client, DeflateConfig::default());

        let compressed = context.compress(&data).unwrap();

        assert_eq!(&context.decompress(&compressed, true, usize::MAX).unwrap(), &data);
    }

    #[test]
    fn decompression_limits_applied() {
        let data = vec![0; 1 << 18];

        let mut context = DeflateContext::new(Role::Client, DeflateConfig::default());
        let compressed = context.compress(&data).unwrap();

        // A buffer of all zeros compresses very well.
        assert!(compressed.len() < data.len() / 500);

        assert_eq!(
            context.decompress(&compressed, true, data.len() - 1),
            Err(DecompressionError::SizeLimitReached)
        );
    }

    #[test]
    fn compressible_payload_prefixes() {
        let _ = env_logger::try_init();
        let data: Vec<u8> = rand::distr::Alphanumeric
            .sample_iter(&mut rand::rngs::SmallRng::from_seed([59; 32]))
            .take(1 << 16)
            .collect();

        let prefixes =
            (5..).map(|i| 1 << i).take_while(|len| *len <= data.len()).map(|len| &data[..len]);

        for prefix in prefixes {
            let mut context = DeflateContext::new(Role::Client, DeflateConfig::default());
            println!("compressing {} bytes of compressible data", prefix.len());

            let compressed = context.compress(prefix).unwrap();
            assert_eq!(context.decompress(&compressed, true, usize::MAX).unwrap(), prefix);
        }
    }

    /// Utilities for testing decomrpession of highly-compressed payloads.
    pub(crate) mod very_compressed {
        use bytes::Bytes;

        // Compressed payload that decompresses to 50KB of zeroes. This was
        // specifically chosen so that its compressed form aligns with a byte
        // boundary, which lets us repeat it an arbitrary number of times to
        // form the payload of a single message.
        pub(crate) const FRAME_PAYLOAD: &[u8; 66] = &[
            0xec, 0xc1, 0x31, 0x01, 0x00, 0x00, 0x00, 0xc2, 0xa0, 0xf5, 0x4f, 0x6d, 0x0b, 0x2f,
            0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x6f,
        ];
        pub(crate) const DECOMPRESSED_LEN: usize = 50 * 1024;

        pub(crate) fn make_frames(frame_count: usize) -> impl Iterator<Item = (Bytes, bool)> {
            std::iter::repeat_n(FRAME_PAYLOAD, frame_count).enumerate().map(move |(i, bytes)| {
                let is_final = i == frame_count - 1;
                let bytes = if is_final {
                    bytes.iter().copied().chain(std::iter::once(0x00)).collect()
                } else {
                    Bytes::from_static(bytes)
                };
                (bytes, is_final)
            })
        }
    }

    /// A single frame built from repeated `very_compressed` blocks, plus the
    /// trailing empty-block header byte `make_frames` puts on its final frame.
    fn bomb_payload(copies: usize) -> Vec<u8> {
        let mut payload = very_compressed::FRAME_PAYLOAD.repeat(copies);
        payload.push(0x00);
        payload
    }

    /// Input that would inflate a thousandfold, against a budget far below it.
    /// The budget is enforced inside the inflate loop rather than after it, so
    /// this errors within an iteration of crossing the limit instead of
    /// materializing the payload first. The assertions cover the error and the
    /// scale; that the process never grows to the inflated size is a property
    /// only an external memory measurement can show.
    #[test]
    fn decompression_limit_stops_a_bomb_mid_stream() {
        let _ = env_logger::try_init();

        let mut context = DeflateContext::new(Role::Client, DeflateConfig::default());
        assert_eq!(
            context.decompress(&bomb_payload(20_000), true, 1 << 20),
            Err(DecompressionError::SizeLimitReached)
        );
    }

    /// The control the test above needs: without a budget the same fixture
    /// really does inflate 776:1, so an implementation that checked the limit
    /// only after inflating would have been caught rather than passing quietly.
    #[test]
    fn very_compressed_payload_inflates_fully_without_limit() {
        let _ = env_logger::try_init();

        let mut context = DeflateContext::new(Role::Client, DeflateConfig::default());
        let out = context.decompress(&bomb_payload(2_000), true, usize::MAX).unwrap();
        assert_eq!(out.len(), 2_000 * very_compressed::DECOMPRESSED_LEN);
        assert!(out.iter().all(|b| *b == 0));
    }

    #[test]
    fn large_message_decompression() {
        let _ = env_logger::try_init();

        for frame_count in 1..=10 {
            let mut context = DeflateContext::new(Role::Client, DeflateConfig::default());

            let decompressed: Bytes = very_compressed::make_frames(frame_count)
                .enumerate()
                .flat_map(|(i, (frame, is_final))| {
                    context
                        .decompress
                        .decompress(&frame, is_final, usize::MAX)
                        .unwrap_or_else(|e| panic!("deflating frame {i}/{frame_count} failed: {e}"))
                })
                .collect();
            assert!(decompressed.iter().all(|b| *b == 0));
            assert_eq!(decompressed.len(), frame_count * very_compressed::DECOMPRESSED_LEN);
        }
    }

    #[test]
    fn decompress_multiple_messages_that_each_set_bfinal() {
        let _ = env_logger::try_init();

        let mut rng = rand::rngs::SmallRng::from_seed([12; 32]);
        let uncompressed_payloads = std::iter::repeat_with(|| {
            let mut data: Vec<u8> = vec![0; 1 << 12];
            rng.fill_bytes(&mut data);
            data
        });

        let mut context = DeflateContext::new(Role::Server, DeflateConfig::default());

        for (i, payload) in uncompressed_payloads.enumerate().take(5) {
            let mut compressed = context.compress(&payload).unwrap().try_into_mut().unwrap();
            // The final block in the stream is a 5-byte uncompressed block, but
            // with the trailing 4 bytes of the body chopped off (per the RFC).
            // We don't know where in the last *byte* the final block begins
            // (since DEFLATE is a bit-oriented protocol), so to make sure the
            // payload ends with a block with BFINAL set we need to append
            // another block. First we reattach the chopped-off bytes from the
            // last block. Then we push *another* 5-byte uncompressed block with
            // BFINAL set. Lastly we chop off the trailing 4 bytes per the spec.
            compressed.extend_from_slice(ELIDED_TRAILER_BLOCK_CONTENTS);
            compressed.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
            compressed.truncate(compressed.len() - ELIDED_TRAILER_BLOCK_CONTENTS.len());

            println!("decompressing block {i}");
            let decompressed = context.decompress(&compressed, true, usize::MAX).unwrap();
            assert_eq!(decompressed.len(), payload.len());
            assert_eq!(decompressed, payload);
        }
    }

    mod rfc_7692_section_7_2_3_examples {
        use super::*;

        #[test]
        fn one_block() {
            // From RFC 7692 Section 7.2.3.1:
            //
            //   Suppose that an endpoint sends a text message "Hello".  If the
            //   endpoint uses one compressed DEFLATE block (compressed with fixed
            //   Huffman code and the "BFINAL" bit not set) to compress the message,
            //   the endpoint obtains the compressed data to use for the message
            //   payload as follows.
            //
            //   The endpoint compresses "Hello" into one compressed DEFLATE block and
            //   flushes the resulting data into a byte array using an empty DEFLATE
            //   block with no compression:
            //
            //       0xf2 0x48 0xcd 0xc9 0xc9 0x07 0x00 0x00 0x00 0xff 0xff
            //
            //   By stripping 0x00 0x00 0xff 0xff from the tail end, the endpoint gets
            //   the data to use for the message payload:
            //
            const EXPECTED_COMPRESSED_PAYLOAD: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

            let mut context = DeflateContext::new(Role::Server, DeflateConfig::default());
            let compressed = context.compress(b"Hello").unwrap();
            assert_eq!(&compressed[..], EXPECTED_COMPRESSED_PAYLOAD);
            //
            //   ...
            //
            //   Suppose that the endpoint sends the compressed message with
            //   fragmentation.  The endpoint splits the compressed data into
            //   fragments and builds frames for each fragment.  For example, if the
            //   fragments are 3 and 4 octets,
            //
            const FRAGMENTED_FRAMES: &[&[u8]] = &[
                //  the first frame is:
                &[0x41, 0x03, 0xf2, 0x48, 0xcd],
                //   and the second frame is:
                &[0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00],
            ];
            //
            //   Note that the RSV1 bit is set only on the first frame.

            let frame_payloads =
                FRAGMENTED_FRAMES.iter().map(|frame| &frame[2..]).collect::<Vec<_>>();

            let decompressed = frame_payloads
                .iter()
                .enumerate()
                .map(|(index, payload)| {
                    context.decompress(payload, index == frame_payloads.len() - 1, usize::MAX)
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .concat();

            assert_eq!(decompressed, b"Hello");
        }

        #[test]
        fn sharing_sliding_window() {
            const ROLE: Role = Role::Client;

            // From RFC 7692 Section 7.2.3.2:
            //
            //   Suppose that a client has sent a message "Hello" as a compressed
            //   message and will send the same message "Hello" again as a compressed
            //   message.
            //
            const FIRST_PAYLOAD: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
            //
            //   The above is the payload of the first message that the client has
            //   sent.  If the "agreed parameters" contain the
            //   "client_no_context_takeover" extension parameter, the client
            //   compresses the payload of the next message into the same bytes (if
            //   the client uses the same "BTYPE" value and "BFINAL" value).  So, the
            //   payload of the second message will be:
            //
            const SECOND_PAYLOAD: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

            let mut context = DeflateContext::new(
                ROLE,
                DeflateConfig::default().set_no_context_takeover(ROLE, true),
            );
            assert_eq!(&context.compress(b"Hello").unwrap()[..], FIRST_PAYLOAD);
            assert_eq!(&context.compress(b"Hello").unwrap()[..], SECOND_PAYLOAD);

            //
            //   If the "agreed parameters" did not contain the
            //   "client_no_context_takeover" extension parameter, the client can
            //   compress the payload of the next message into fewer bytes by
            //   referencing the history in the LZ77 sliding window.  So, the payload
            //   of the second message will be:
            //
            const NEW_SECOND_PAYLOAD: &[u8] = &[0xf2, 0x00, 0x11, 0x00, 0x00];

            let mut context = DeflateContext::new(ROLE, DeflateConfig::default());
            assert_eq!(&context.compress(b"Hello").unwrap()[..], FIRST_PAYLOAD);
            assert_eq!(&context.compress(b"Hello").unwrap()[..], NEW_SECOND_PAYLOAD);
        }

        #[test]
        fn deflate_block_with_bfinal_set() {
            // From RFC 7692 Section 7.2.3.4:
            //
            //   On platforms on which the flush method using an empty DEFLATE
            //   block with no compression is not available, implementors can
            //   choose to flush data using DEFLATE blocks with "BFINAL" set to
            //   1.

            const PAYLOAD: &[u8] = &[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00];

            //   This is the payload of a message containing "Hello" compressed
            //   using a DEFLATE block with "BFINAL" set to 1.  The first 7
            //   octets constitute a DEFLATE block with "BFINAL" set to 1 and
            //   "BTYPE" set to 01 containing "Hello".  The last 1 octet (0x00)
            //   contains the header bits with "BFINAL" set to 0 and "BTYPE" set
            //   to 00, and 5 padding bits of 0.  This octet is necessary to
            //   allow the payload to be decompressed in the same manner as
            //   messages flushed using DEFLATE blocks with "BFINAL" unset.

            let mut context = DeflateContext::new(Role::Client, DeflateConfig::default());
            assert_eq!(
                context.decompress(PAYLOAD, true, usize::MAX),
                Ok(Bytes::from_static(b"Hello"))
            );
        }

        #[test]
        fn two_deflate_blocks() {
            // From RFC 7692 Section 7.2.3.5:
            //
            //   Two or more DEFLATE blocks may be used in one message.

            const TWO_BLOCKS: &[u8] =
                &[0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00];

            let mut context = DeflateContext::new(Role::Client, DeflateConfig::new());

            assert_eq!(&context.decompress(TWO_BLOCKS, true, usize::MAX).unwrap()[..], b"Hello");
        }
    }
}
