//! [Per-Message Compression Extensions][rfc7692]
//!
//! [rfc7692]: https://tools.ietf.org/html/rfc7692

use bytes::Bytes;
use thiserror::Error;

#[cfg(feature = "deflate")]
pub mod deflate;

/// Active context for performing per-message compression.
///
/// Uninhabited when no PMCE is compiled in, so [`Extensions`] can hold the
/// field unconditionally and the `None` case needs no special handling.
///
/// [`Extensions`]: crate::extensions::Extensions
#[cfg(feature = "deflate")]
pub type PerMessageCompressionContext = deflate::DeflateContext;

/// Active context for performing per-message compression.
#[cfg(not(feature = "deflate"))]
pub type PerMessageCompressionContext = core::convert::Infallible;

/// Error encountered while compressing or decompressing.
#[derive(Copy, Clone, Debug, Error, PartialEq, Eq)]
pub enum CompressionError {
    /// Error encountered while deflating or inflating
    #[error("Deflate error: {0}")]
    #[cfg(feature = "deflate")]
    Deflate(deflate::DeflateError),
}

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(not(feature = "deflate"), allow(dead_code))]
pub(crate) enum DecompressionError<E = CompressionError> {
    /// The decompressed frame is larger than the configured limit.
    #[error("decompressed data is too large")]
    SizeLimitReached,
    /// An error was encountered while decompressing.
    #[error("{0}")]
    Decompression(E),
}

#[cfg(feature = "deflate")]
#[inline]
pub(crate) fn compress(
    context: &mut PerMessageCompressionContext,
    payload: &Bytes,
) -> Result<Bytes, CompressionError> {
    context.compress(payload).map_err(CompressionError::Deflate)
}

#[cfg(feature = "deflate")]
#[inline]
pub(crate) fn decompress(
    context: &mut PerMessageCompressionContext,
    payload: &Bytes,
    is_final: bool,
    size_limit: usize,
) -> Result<Bytes, DecompressionError> {
    context.decompress(payload, is_final, size_limit).map_err(|e| e.map(CompressionError::Deflate))
}

#[cfg(not(feature = "deflate"))]
pub(crate) fn compress(
    context: &mut PerMessageCompressionContext,
    _payload: &Bytes,
) -> Result<Bytes, CompressionError> {
    match *context {}
}

#[cfg(not(feature = "deflate"))]
pub(crate) fn decompress(
    context: &mut PerMessageCompressionContext,
    _payload: &Bytes,
    _is_final: bool,
    _size_limit: usize,
) -> Result<Bytes, DecompressionError> {
    match *context {}
}

impl<E> DecompressionError<E> {
    #[cfg_attr(not(feature = "deflate"), allow(dead_code))]
    pub(crate) fn map<T>(self, f: impl FnOnce(E) -> T) -> DecompressionError<T> {
        match self {
            Self::SizeLimitReached => DecompressionError::SizeLimitReached,
            Self::Decompression(e) => DecompressionError::Decompression(f(e)),
        }
    }
}

impl<E: Into<std::io::Error>> From<E> for DecompressionError<std::io::Error> {
    fn from(value: E) -> Self {
        Self::Decompression(value.into())
    }
}
