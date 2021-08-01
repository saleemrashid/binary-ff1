use cipher::{
    generic_array::{typenum::Unsigned, GenericArray},
    BlockEncrypt,
};

pub struct PRF<'a, C: BlockEncrypt> {
    cipher: &'a C,
    offset: usize,
    state: GenericArray<u8, C::BlockSize>,
}

impl<'a, C: BlockEncrypt> Copy for PRF<'a, C> where GenericArray<u8, C::BlockSize>: Copy {}

impl<'a, C: BlockEncrypt> Clone for PRF<'a, C>
where
    Self: Copy,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, C: BlockEncrypt> PRF<'a, C>
where
    GenericArray<u8, C::BlockSize>: Copy,
{
    pub fn new(cipher: &'a C) -> Self {
        Self {
            cipher,
            offset: 0,
            state: GenericArray::default(),
        }
    }

    fn ciph(&mut self) {
        self.cipher.encrypt_block(&mut self.state);
    }

    pub fn seek(&mut self, n: usize) {
        let offset = self.offset + n;
        for _ in 0..(offset / C::BlockSize::to_usize()) {
            self.ciph();
        }
        self.offset = offset % C::BlockSize::to_usize();
    }

    pub fn write(&mut self, buf: &[u8]) {
        let offset = self.offset;
        let needed = C::BlockSize::to_usize() - offset;

        if needed > buf.len() {
            xor_slice(&mut self.state[offset..offset + buf.len()], buf);
            self.offset += buf.len();
        } else {
            xor_slice(&mut self.state[offset..], &buf[..needed]);
            self.ciph();

            if buf.len() > needed {
                let mut chunks = buf[needed..].chunks_exact(C::BlockSize::to_usize());

                for block in chunks.by_ref() {
                    xor_slice(&mut self.state, block);
                    self.ciph();
                }

                let remainder = chunks.remainder();
                xor_slice(&mut self.state[..remainder.len()], remainder);
                self.offset = remainder.len();
            } else {
                self.offset = 0;
            }
        }
    }

    pub fn generate_s<'b>(&'b self, len: usize) -> impl Iterator<Item = u8> + 'b {
        let num_blocks = (len + C::BlockSize::to_usize() - 1) / C::BlockSize::to_usize();
        (0..num_blocks as u32)
            .flat_map(move |i| self.expand(i).into_iter())
            .rev()
            .skip(num_blocks * C::BlockSize::to_usize() - len)
    }

    pub fn expand(&self, i: u32) -> GenericArray<u8, C::BlockSize> {
        let mut state = self.output();
        if i > 0 {
            xor_slice(&mut state[C::BlockSize::to_usize() - 4..], &i.to_be_bytes());
            self.cipher.encrypt_block(&mut state);
        }
        state
    }

    pub fn output(&self) -> GenericArray<u8, C::BlockSize> {
        assert_eq!(self.offset, 0, "incomplete block");
        self.state
    }
}

fn xor_slice(dst: &mut [u8], src: &[u8]) {
    assert_eq!(
        dst.len(),
        src.len(),
        "destination and source slices have different lengths"
    );
    for (lhs, &rhs) in dst.iter_mut().zip(src.iter()) {
        *lhs ^= rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::PRF;

    use aes::{
        cipher::{
            generic_array::{typenum::Unsigned, GenericArray},
            BlockCipher, NewBlockCipher,
        },
        Aes256,
    };

    use lazy_static::lazy_static;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use rand::RngCore;

    type BlockSize = <Aes256 as BlockCipher>::BlockSize;

    const MAX_INPUT_SIZE: usize = 8192;

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

    fn valid_input_size(args: &[usize]) -> bool {
        args.iter()
            .copied()
            .try_fold(0, usize::checked_add)
            .map_or(false, |n| {
                n <= MAX_INPUT_SIZE && n % BlockSize::to_usize() == 0
            })
    }

    fn random_bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0; n];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    /// Test that seeking is equivalent to writing zeroes.
    #[quickcheck]
    fn seek_equivalent_to_write(i: usize, j: usize, k: usize) -> TestResult {
        if !valid_input_size(&[i, j, k]) {
            return TestResult::discard();
        }

        let random = random_bytes(j);

        let expected = {
            let mut buf = vec![0; i + j + k];
            buf[i..i + j].copy_from_slice(&random);
            let mut prf = PRF::new(&*CIPHER);
            prf.write(&buf);
            prf.output()
        };

        let output = {
            let mut prf = PRF::new(&*CIPHER);
            prf.seek(i);
            prf.write(&random);
            prf.seek(k);
            prf.output()
        };

        TestResult::from_bool(output == expected)
    }

    /// Test that writing bytes individually is equivalent to writing the entire
    /// buffer.
    #[quickcheck]
    fn write_bytes_individually(n: usize) -> TestResult {
        if !valid_input_size(&[n]) {
            return TestResult::discard();
        }

        let buf = random_bytes(n);

        let expected = {
            let mut prf = PRF::new(&*CIPHER);
            prf.write(&buf);
            prf.output()
        };

        let output = {
            let mut prf = PRF::new(&*CIPHER);
            for &x in &buf {
                prf.write(&[x])
            }
            prf.output()
        };

        TestResult::from_bool(output == expected)
    }

    /// Test that writing four different-sized chunks separately is equivalent
    /// to concatenating them.
    #[quickcheck]
    fn write_chunks_separately(i: usize, j: usize, k: usize, l: usize) -> TestResult {
        if !valid_input_size(&[i, j, k, l]) {
            return TestResult::discard();
        }

        let chunks = [
            random_bytes(i),
            random_bytes(j),
            random_bytes(k),
            random_bytes(l),
        ];

        let expected = {
            let mut prf = PRF::new(&*CIPHER);
            prf.write(&chunks.concat());
            prf.output()
        };

        let output = {
            let mut prf = PRF::new(&*CIPHER);
            for chunk in &chunks {
                prf.write(chunk);
            }
            prf.output()
        };

        TestResult::from_bool(output == expected)
    }
}
