//! Optimized Rust implementation of FF1 encryption with radix 2, specified in
//! [NIST Special Publication 800-38G](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf).
//!
//! # Example
//!
//! ```rust
//! # use aes::{
//! #     cipher::{generic_array::GenericArray, NewBlockCipher},
//! #     Aes256,
//! # };
//! # use binary_ff1::BinaryFF1;
//! #
//! const KEY: [u8; 32] = [0; 32];
//! const LEN: usize = 3;
//!
//! let cipher = Aes256::new(GenericArray::from_slice(&KEY));
//! let mut scratch = [0; LEN + 1];
//! let mut ff1 = BinaryFF1::new(&cipher, LEN, &[], &mut scratch).unwrap();
//!
//! let mut x: [u8; LEN] = [0xAB, 0xCD, 0xEF];
//! ff1.encrypt(&mut x).unwrap();
//! assert_eq!(x, [0x75, 0xFB, 0x62]);
//! ff1.decrypt(&mut x).unwrap();
//! assert_eq!(x, [0xAB, 0xCD, 0xEF]);
//! ```

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

mod error;
mod ff1;
mod limb;
mod prf;

pub use crate::{error::Error, ff1::BinaryFF1};

use crate::{limb::Limbs, prf::PRF};
