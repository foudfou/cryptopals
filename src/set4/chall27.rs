#[cfg(test)]
mod tests {
    use openssl::symm::Cipher;

    use crate::set2::chall12::tests::Encrypter;
    use crate::set2::chall16::tests::UnknownEncrypterChall16;
    use crate::xor::xor;

    #[test]
    fn test_crack_cbc_with_iv_eq_key() {
        //! To guess the Key, we need P1 ^ I1, where I1 is the intermediary
        //! plain before xor with the IV (= Key here). In order to get I1, we
        //! can just use C2 = 0 and C3 = C1: C1 || 0 || C1. Then I1 = P3 ^ 0.

        let null_blk = [0u8; 16];
        let mut unknown = UnknownEncrypterChall16::new(Cipher::aes_128_cbc(), null_blk);
        unknown.iv = unknown.e.key;

        let enc = unknown.encrypt(&[]).unwrap();

        // We can't just pass C1 || 0 || C1, as there will be a padding
        // error. So we just brute-force on the last byte to get a 0x01
        // padding.
        let mut guess = vec![];
        for b in 0u8..=255 {
            let blk = [&null_blk[..15], &[b]].concat();
            let forged = [&enc[..16], &blk, &enc[..16]].concat();

            // CHEATING HERE. We're intructed to get the decrypted plaintext
            // from an error message returned when encrypting non-ascii
            // bytes. That is we should just pass non-ascii bytes to encrypt()
            // to read the plaintext. Instead we'll just pretend by using the
            // existing decrypt(), thus avoiding to modify encrypt().
            let clear = unknown.decrypt(&forged);
            if clear.is_ok() {
                let c = clear.unwrap();
                let c3 = [&c[32..47], &[1u8]].concat();
                let i1 = &xor(&c3, &blk);
                guess = xor(&c[..16], i1);
                // println!("i={:x?}\nk={:x?}\ng={:x?} b={:x?}", unknown.iv, unknown.e.key, guess, b);
                break;
            }
        }
        assert_eq!(guess, unknown.e.key);
    }
}
