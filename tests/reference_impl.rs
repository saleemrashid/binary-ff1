use aes::{
    cipher::{generic_array::GenericArray, NewBlockCipher},
    Aes128,
};
use binary_ff1::BinaryFF1;
use fpe::ff1::{BinaryNumeralString, FF1};

use lazy_static::lazy_static;
use quickcheck::TestResult;
use quickcheck_macros::quickcheck;

const KEY: [u8; 16] = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
];

lazy_static! {
    static ref CIPHER: Aes128 = Aes128::new(GenericArray::from_slice(&KEY));
    static ref FF: FF1::<Aes128> = FF1::new(&KEY, 2).unwrap();
}

#[quickcheck]
fn reference_impl(tweak: Vec<u8>, x: Vec<u8>) -> TestResult {
    let mut scratch = vec![0; x.len() + 1];
    let mut ff1 = BinaryFF1::new(&*CIPHER, x.len(), &tweak, &mut scratch).unwrap();

    let mut ct = x.clone();
    ff1.encrypt(&mut ct).unwrap();

    let mut pt = x.clone();
    ff1.decrypt(&mut pt).unwrap();

    let ns = BinaryNumeralString::from_bytes_le(&x);
    let expected_ct = FF.encrypt(&tweak, &ns).unwrap().to_bytes_le();
    let expected_pt = FF.decrypt(&tweak, &ns).unwrap().to_bytes_le();

    TestResult::from_bool(ct == expected_ct && pt == expected_pt)
}
