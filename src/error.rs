/// Errors related to FF1 encryption.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Input length is not the same as the length defined in the
    /// [`BinaryFF1`](crate::BinaryFF1) structure.
    InvalidInputLength,
    /// Scratch buffer too small for desired input length.
    ScratchTooSmall,
}
