use block_cipher_trait::{
    generic_array::{typenum::U16, ArrayLength, GenericArray},
    BlockCipher,
};

use crate::{Error, Limbs, PRF};

/// A struct for performing FF1 encryption in radix 2.
///
/// The block cipher must have a 16 byte block size and should be AES-128,
/// AES-192, or AES-256.
pub struct BinaryFF1<'a, C: BlockCipher> {
    limbs: Limbs<'a>,
    prf: PRF<'a, C>,
    s_len: usize,
}

impl<'a, C> BinaryFF1<'a, C>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    /// Creates an [`BinaryFF1`] instance for a given block cipher, input
    /// length, and tweak. The scratch buffer must be at least `len + 1`
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScratchTooSmall`] if the scratch buffer is too small.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use aes::{
    /// #     block_cipher_trait::{generic_array::GenericArray, BlockCipher},
    /// #     Aes256,
    /// # };
    /// # use binary_ff1::{BinaryFF1, Error};
    /// #
    /// # let cipher = Aes256::new(GenericArray::from_slice(&[0; 32]));
    /// # let tweak = [];
    /// let mut scratch = vec![0; 128];
    ///
    /// assert!(BinaryFF1::new(&cipher, 126, &tweak, &mut scratch).is_ok());
    /// assert!(BinaryFF1::new(&cipher, 127, &tweak, &mut scratch).is_ok());
    ///
    /// // Scratch buffer must be at least len + 1 bytes
    /// assert_eq!(
    ///     BinaryFF1::new(&cipher, 128, &tweak, &mut scratch).err(),
    ///     Some(Error::ScratchTooSmall)
    /// );
    /// ```
    pub fn new(
        cipher: &'a C,
        len: usize,
        tweak: &[u8],
        scratch: &'a mut [u8],
    ) -> Result<Self, Error> {
        // For an odd-numbered input length, the integers are not on byte boundaries.
        // For example, an 11 byte input contains two 44-bit integers. We work
        // around this by loading them into a scratch buffer, performing the
        // encryption algorithm, and storing them back into the output buffer.
        let limbs = Limbs::new(len, scratch)?;

        let num_bits = (len * 8) as u32;
        let tweak_len = tweak.len() as u32;

        // 4. Let d = 4 * ceil(b / 4) + 4
        let s_len = ((limbs.limb_len + 3) & !3) + 4;

        // This can be precomputed so we only do one AES block encryption, rather than
        // computing and encrypting it every time the user calls encrypt.
        let mut block = [0; 16];
        // 5. Let P =
        block[0] = 1; // [1]^1
        block[1] = 2; // [2]^1
        block[2] = 1; // [1]^1
        block[5] = 2; // [radix]^3
        block[6] = 10; // [10]^1
        block[7] = (num_bits / 2) as u8; // [u mod 256]^1
        block[8..12].copy_from_slice(&num_bits.to_be_bytes()); // [n]^4
        block[12..].copy_from_slice(&tweak_len.to_be_bytes()); // [t]^4

        let mut prf = PRF::new(cipher);
        prf.write(&block);
        // The specification recomputes the entirety of Q in each Feistel round, but the
        // beginning of Q can be precomputed here. If the tweak spans multiple
        // blocks, this will also save us a few AES block encryptions.
        prf.write(tweak);
        // The specification defines this as [0]^((-t-b-1) mod 16). It is used to pad
        // the input to the PRF function to a multiple of the block size (16
        // bytes).
        prf.seek(!(tweak.len() + limbs.limb_len) & 15);

        Ok(Self { limbs, prf, s_len })
    }

    /// Encrypts the given plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInputLength`] if the length of `x` is not the
    /// same as the input length defined in this [`BinaryFF1`] structure.
    pub fn encrypt(&mut self, x: &mut [u8]) -> Result<(), Error> {
        self.limbs.load(x)?;

        for i in 0..10 {
            // This is equivalent to Step 6viii and 6ix in the specification, where A and B
            // are swapped at the end of each Feistel round.
            let (x_a, x_b) = if i % 2 == 0 {
                (&mut self.limbs.upper, &self.limbs.lower)
            } else {
                (&mut self.limbs.lower, &self.limbs.upper)
            };

            // This is the remainder of Q. It is specific to a given Feistel round of a
            // given plaintext, so we cannot precompute it.
            let mut prf = self.prf;
            prf.write(&[i]);
            prf.write(x_b.buf);

            // generate_s will panic if an incomplete block has been written to the PRF,
            // i.e. the input was not a multiple of the block size. This cannot
            // happen here because the PRF input was padded in the constructor.
            x_a.add_s(prf.generate_s(self.s_len));
        }

        self.limbs.store(x).unwrap();
        Ok(())
    }

    /// Decrypts the given ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInputLength`] if the length of `x` is not the
    /// same as the input length defined in this [`BinaryFF1`] structure.
    pub fn decrypt(&mut self, x: &mut [u8]) -> Result<(), Error> {
        self.limbs.load(x)?;

        // This is the inverse of our encryption routine: we iterate backwards, and
        // subtract instead of adding.
        for i in (0..10).rev() {
            let (x_a, x_b) = if i % 2 == 0 {
                (&mut self.limbs.upper, &self.limbs.lower)
            } else {
                (&mut self.limbs.lower, &self.limbs.upper)
            };

            let mut prf = self.prf;
            prf.write(&[i]);
            prf.write(x_b.buf);

            x_a.sub_s(prf.generate_s(self.s_len));
        }

        self.limbs.store(x).unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryFF1;

    use aes::{
        block_cipher_trait::{generic_array::GenericArray, BlockCipher},
        Aes256,
    };

    use lazy_static::lazy_static;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    lazy_static! {
        static ref CIPHER: Aes256 = {
            const KEY: [u8; 32] = [
                0xF9, 0xE8, 0x38, 0x9F, 0x5B, 0x80, 0x71, 0x2E, 0x38, 0x86, 0xCC, 0x1F, 0xA2, 0xD2,
                0x8A, 0x3B, 0x8C, 0x9C, 0xD8, 0x8A, 0x2D, 0x4A, 0x54, 0xC6, 0xAA, 0x86, 0xCE, 0x0F,
                0xEF, 0x94, 0x4B, 0xE0,
            ];
            Aes256::new(GenericArray::from_slice(&KEY))
        };
    }

    macro_rules! a_then_b {
        ($tweak:ident, $x:ident, $a:ident, $b:ident) => {{
            let mut scratch = vec![0; $x.len() + 1];
            let mut ff1 = BinaryFF1::new(&*CIPHER, $x.len(), &$tweak, &mut scratch).unwrap();

            let mut output = $x.clone();
            ff1.$a(&mut output).unwrap();
            ff1.$b(&mut output).unwrap();

            TestResult::from_bool(output == $x)
        }};
    }

    /// Test that a [`BinaryFF1`] instance can encrypt and decrypt a plaintext.
    #[quickcheck]
    fn encrypt_then_decrypt(tweak: Vec<u8>, x: Vec<u8>) -> TestResult {
        a_then_b!(tweak, x, encrypt, decrypt)
    }

    /// Test that a [`BinaryFF1`] instance can decrypt and encrypt a ciphertext.
    #[quickcheck]
    fn decrypt_then_encrypt(tweak: Vec<u8>, x: Vec<u8>) -> TestResult {
        a_then_b!(tweak, x, decrypt, encrypt)
    }

    /// Test that a [`BinaryFF1`] instance can be used to encrypt multiple
    /// plaintexts of the same length.
    ///
    /// This ensures that we do not mutate the instance in a way that affects
    /// future encryption operations.
    #[quickcheck]
    fn encrypt_reuse_multiple_plaintexts(tweak: Vec<u8>, x1: Vec<u8>, x2: Vec<u8>) -> TestResult {
        if x1.len() != x2.len() || x1 == x2 {
            return TestResult::discard();
        }

        let len = x1.len();
        let mut scratch = vec![0; len + 1];
        let mut ff1 = BinaryFF1::new(&*CIPHER, len, &tweak, &mut scratch).unwrap();

        let mut encrypt = |x: &[u8]| {
            let mut output = x.to_vec();
            ff1.encrypt(&mut output).unwrap();
            output
        };

        // Test two different plaintexts to ensure that the instance does not become
        // plaintext-specific.
        let expected_1 = encrypt(&x1);
        let expected_2 = encrypt(&x2);

        if expected_1 == expected_2 {
            return TestResult::failed();
        }

        TestResult::from_bool(
            (0..10).all(|_| encrypt(&x1) == expected_1 && encrypt(&x2) == expected_2),
        )
    }
}
