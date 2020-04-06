use crate::Error;

pub struct Limbs<'a> {
    pub upper: Limb<'a>,
    pub lower: Limb<'a>,
    len: usize,
    pub limb_len: usize,
    lower_offset: usize,
}

impl<'a> Limbs<'a> {
    pub fn new(len: usize, scratch: &'a mut [u8]) -> Result<Self, Error> {
        let limb_len = (len + 1) / 2;

        if scratch.len() < len + 1 {
            return Err(Error::ScratchTooSmall);
        }

        let lower_offset = len / 2;
        let is_odd = limb_len != lower_offset;

        let (upper_buf, lower_buf) = scratch[..limb_len * 2].split_at_mut(limb_len);
        let upper = Limb::new(upper_buf, is_odd);
        let lower = Limb::new(lower_buf, is_odd);

        Ok(Self {
            upper,
            lower,
            len,
            limb_len,
            lower_offset,
        })
    }

    /// Load the limbs from the buffer, in little-endian bit order.
    pub fn load(&mut self, x: &[u8]) -> Result<(), Error> {
        if x.len() != self.len {
            return Err(Error::InvalidInputLength);
        }
        self.upper.load_as_upper(&x[..self.limb_len]);
        self.lower.load_as_lower(&x[self.lower_offset..]);
        Ok(())
    }

    /// Store the limbs in the buffer, in little-endian bit order.
    pub fn store(&self, x: &mut [u8]) -> Result<(), Error> {
        if x.len() != self.len {
            return Err(Error::InvalidInputLength);
        }
        // We need to the store the upper limb first, in case the limbs share a byte.
        // Storing the upper limb clobbers the byte (therefore should be done first),
        // but storing the lower limb does not (therefore should be done
        // second).
        self.upper.store_as_upper(&mut x[..self.limb_len]);
        self.lower.store_as_lower(&mut x[self.lower_offset..]);
        Ok(())
    }
}

pub struct Limb<'a> {
    // This is a public field and therefore the implementation must ensure this is always a
    // canonical representation of the limb.
    pub buf: &'a mut [u8],
    is_odd: bool,
}

macro_rules! add_and_carry {
    ($self:ident, $s:ident, $method:ident) => {{
        let mut carry = 0_u8;
        for lhs in $self.buf.iter_mut().rev() {
            let rhs = $s.next().unwrap_or(0);
            let (tmp, carry1) = lhs.$method(carry);
            let (tmp, carry2) = tmp.$method(rhs);
            *lhs = tmp;
            carry = u8::from(carry1) | u8::from(carry2);
        }
        if $self.is_odd {
            // If the input had an odd-numbered length, we only use the lower nibble of
            // the most significant byte of this limb. The algorithm will be
            // incorrect if the unused upper nibble is non-zero, because the
            // byte representation of this limb is used in the PRF input.
            $self.buf[0] &= 0xF;
        }
    }};
}

impl<'a> Limb<'a> {
    pub fn new(buf: &'a mut [u8], is_odd: bool) -> Self {
        Self { buf, is_odd }
    }

    fn load_as_upper(&mut self, src: &[u8]) {
        if self.is_odd {
            // The upper limb needs to be shifted right.
            reverse_then_shift_right(self.buf, src);
        } else {
            reverse_no_shift(self.buf, src, false);
        }
    }

    fn load_as_lower(&mut self, src: &[u8]) {
        reverse_no_shift(self.buf, src, false);
        if self.is_odd {
            // add_s has a detailed explanation of why this is necessary.
            self.buf[0] &= 0xF;
        }
    }

    fn store_as_upper(&self, dst: &mut [u8]) {
        if self.is_odd {
            shift_left_then_reverse(dst, self.buf);
        } else {
            reverse_no_shift(dst, self.buf, false);
        }
    }

    fn store_as_lower(&self, dst: &mut [u8]) {
        // The upper limb should be stored first, then this will make sure not to
        // clobber the upper nibble if the upper and lower limbs are sharing a
        // byte.
        reverse_no_shift(dst, self.buf, self.is_odd);
    }

    /// Simple add-and-carry algorithm to add the S value.
    ///
    /// This limb is represented as big-endian, but the iterator is represented
    /// as little-endian. Overflow in the most significant byte is ignored.
    pub fn add_s(&mut self, mut s: impl Iterator<Item = u8>) {
        add_and_carry!(self, s, overflowing_add)
    }

    /// Simple subtract-and-borrow algorithm to subtract the S value.
    ///
    /// This limb is represented as big-endian, but the iterator is represented
    /// as little-endian. Underflow in the most significant byte is ignored.
    pub fn sub_s(&mut self, mut s: impl Iterator<Item = u8>) {
        add_and_carry!(self, s, overflowing_sub)
    }
}

/// Reverse bits in each byte without shifting.
fn reverse_no_shift(dst: &mut [u8], src: &[u8], mut no_clobber: bool) {
    assert_eq!(
        dst.len(),
        src.len(),
        "destination and source slices have different lengths"
    );

    for (lhs, &rhs) in dst.iter_mut().zip(src.iter()) {
        if no_clobber {
            // We write the upper limb to the output buffer first. If the upper and lower
            // limb share a byte, we don't want to clobber the upper nibble of
            // that byte when we're writing the lower limb. For this code to be
            // correct, rhs must equal (rhs & 0xF).
            *lhs |= rhs.reverse_bits();
            no_clobber = false;
        } else {
            *lhs = rhs.reverse_bits();
        }
    }
}

/// Shift left 4 bits, then reverse bits in each byte.
fn shift_left_then_reverse(dst: &mut [u8], src: &[u8]) {
    assert_eq!(
        dst.len(),
        src.len(),
        "destination and source slices have different lengths"
    );

    let mut carry = 0;
    for (lhs, &rhs) in dst.iter_mut().zip(src.iter()).rev() {
        *lhs = (carry | (rhs << 4)).reverse_bits();
        carry = rhs >> 4;
    }
}

/// Reverse bits in each byte, then shift right 4 bits.
fn reverse_then_shift_right(dst: &mut [u8], src: &[u8]) {
    assert_eq!(
        dst.len(),
        src.len(),
        "destination and source slices have different lengths"
    );

    let mut carry = 0;
    for (lhs, &rhs) in dst.iter_mut().zip(src.iter()) {
        let tmp = rhs.reverse_bits();
        *lhs = carry | (tmp >> 4);
        carry = tmp << 4;
    }
}

#[cfg(test)]
mod tests {
    use super::{reverse_no_shift, reverse_then_shift_right, shift_left_then_reverse, Limb, Limbs};

    use num::{
        bigint::{BigInt, BigUint, Sign},
        traits::{Pow, Zero},
    };

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn load_and_store_unchanged(x: Vec<u8>) -> TestResult {
        let mut scratch = vec![0; x.len() + 1];
        let mut limbs = Limbs::new(x.len(), &mut scratch).unwrap();

        limbs.load(&x).unwrap();
        let mut output = vec![0; x.len()];
        limbs.store(&mut output).unwrap();

        TestResult::from_bool(output == x)
    }

    macro_rules! limb_binop {
        ($lhs:ident, $rhs:ident, $is_odd:ident, $method:ident, $bigint_impl:ident) => {{
            if $is_odd && $lhs.is_empty() {
                return TestResult::discard();
            }

            let output = {
                let mut v = $lhs.clone();
                let mut limb = Limb::new(&mut v, $is_odd);
                let s = $rhs.iter().cloned().rev();
                limb.$method(s);
                v
            };

            let expected = {
                let a = BigUint::from_bytes_be(&$lhs);
                let y = BigUint::from_bytes_be(&$rhs);
                let m = $lhs.len() * 8 - ($is_odd as usize) * 4;
                let modulus = BigUint::from(2_u32).pow(m);
                let c = $bigint_impl(a, y, modulus);

                if c.is_zero() {
                    vec![0; $lhs.len()]
                } else {
                    // BigUint is little-endian, so this is more efficient than using to_bytes_be
                    let mut v = c.to_bytes_le();
                    if v.len() < $lhs.len() {
                        v.resize($lhs.len(), 0);
                    }
                    v.reverse();
                    v
                }
            };

            TestResult::from_bool(output == expected)
        }};
    }

    #[quickcheck]
    fn limb_add(lhs: Vec<u8>, rhs: Vec<u8>, is_odd: bool) -> TestResult {
        fn bigint_impl(a: BigUint, y: BigUint, modulus: BigUint) -> BigUint {
            // 6. vi. Let c = (NUM_radix(A) + y) mod (radix ^ m)
            (a + y) % modulus
        }

        limb_binop!(lhs, rhs, is_odd, add_s, bigint_impl)
    }

    #[quickcheck]
    fn limb_sub(lhs: Vec<u8>, rhs: Vec<u8>, is_odd: bool) -> TestResult {
        fn bigint_impl(a: BigUint, y: BigUint, modulus: BigUint) -> BigUint {
            // 6. vi. Let c = (NUM_radix(A) - y) mod (radix ^ m)
            let a = BigInt::from(a);
            let y = BigInt::from(y);
            let modulus = BigInt::from(modulus);
            let mut c = (a - y) % &modulus;
            if c.sign() == Sign::Minus {
                c += &modulus;
            }
            c.to_biguint().unwrap()
        }

        limb_binop!(lhs, rhs, is_odd, sub_s, bigint_impl)
    }

    #[quickcheck]
    fn reverse_no_shift_unchanged(x: Vec<u8>) -> TestResult {
        let mut tmp = vec![0; x.len()];
        let mut output = vec![0; x.len()];

        reverse_no_shift(&mut tmp, &x, false);
        reverse_no_shift(&mut output, &tmp, false);

        TestResult::from_bool(output == x)
    }

    #[quickcheck]
    fn reverse_and_shift_unchanged(x: Vec<u8>) -> TestResult {
        let mut tmp = vec![0; x.len()];
        let mut output = vec![0; x.len()];

        if x.last().unwrap_or(&0) & 0xF0 == 0 {
            reverse_then_shift_right(&mut tmp, &x);
            shift_left_then_reverse(&mut output, &tmp);
        } else if x.first().unwrap() & 0xF0 == 0 {
            shift_left_then_reverse(&mut tmp, &x);
            reverse_then_shift_right(&mut output, &tmp);
        } else {
            return TestResult::discard();
        }

        TestResult::from_bool(output == x)
    }
}
