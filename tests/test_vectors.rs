use aes::{
    cipher::{generic_array::GenericArray, NewBlockCipher},
    Aes256,
};
use binary_ff1::BinaryFF1;

#[test]
fn zcash_test_vectors() {
    const KEY: [u8; 32] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC,
        0x6A, 0x94,
    ];
    const LEN: usize = 11;

    let cipher = Aes256::new(GenericArray::from_slice(&KEY));
    let mut scratch = vec![0; LEN + 1];

    let mut ff1 = BinaryFF1::new(&cipher, LEN, &[], &mut scratch).unwrap();

    let x = vec![0; LEN];
    let mut output = x.clone();
    ff1.encrypt(&mut output).unwrap();
    assert_eq!(
        output,
        [0x90, 0xAC, 0xEE, 0x3F, 0x83, 0xCD, 0xE7, 0xAE, 0x56, 0x22, 0xF3]
    );
    ff1.decrypt(&mut output).unwrap();
    assert_eq!(output, x);

    ff1.encrypt(&mut output).unwrap();
    ff1.encrypt(&mut output).unwrap();
    assert_eq!(
        output,
        [0x5B, 0x8B, 0xF1, 0x20, 0xF3, 0x9B, 0xAB, 0x85, 0x27, 0xEA, 0x1B]
    );
    ff1.decrypt(&mut output).unwrap();
    ff1.decrypt(&mut output).unwrap();
    assert_eq!(output, x);

    let x = vec![0xAA; LEN];
    let mut output = x.clone();
    ff1.encrypt(&mut output).unwrap();
    assert_eq!(
        output,
        [0xF0, 0x82, 0xB7, 0xEE, 0x8F, 0x29, 0xC0, 0x76, 0x91, 0xCE, 0x64]
    );
    ff1.decrypt(&mut output).unwrap();
    assert_eq!(output, x);

    let tweak = (0..255).collect::<Vec<_>>();
    let mut ff1 = BinaryFF1::new(&cipher, LEN, &tweak, &mut scratch).unwrap();

    ff1.encrypt(&mut output).unwrap();
    assert_eq!(
        output,
        [0xBE, 0x11, 0xB8, 0x86, 0xA8, 0x05, 0x9C, 0x27, 0x51, 0x7B, 0xC5]
    );
    ff1.decrypt(&mut output).unwrap();
    assert_eq!(output, x);
}
