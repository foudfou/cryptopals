#[cfg(test)]
pub mod tests {
    use std::str;

    use openssl::symm::{decrypt, encrypt, Cipher};

    use set2::chall12::tests::{Encrypter, UnknownEncrypter};
    use set2::chall14::tests::detect_blk_size;

    pub struct UnknownEncrypterChall16 {
        e: UnknownEncrypter,
        cipher: Cipher,
        iv: [u8; 16],
        pub pre: Vec<u8>,
        suf: Vec<u8>,
    }

    impl UnknownEncrypterChall16 {
        pub fn new(cipher: Cipher) -> UnknownEncrypterChall16 {
            UnknownEncrypterChall16 {
                e: UnknownEncrypter::new(),
                cipher: cipher,
                iv: [b'\x00'; 16],
                pre: b"comment1=cooking%20MCs;userdata=".to_vec(),
                suf: b";comment2=%20like%20a%20pound%20of%20bacon".to_vec(),
            }
        }

        // For testing purpose.
        pub fn build(cipher: Cipher, pre: &[u8], suf: &[u8]) -> UnknownEncrypterChall16 {
            UnknownEncrypterChall16 {
                e: UnknownEncrypter::new(),
                cipher: cipher,
                iv: [b'\x00'; 16],
                pre: pre.to_vec(),
                suf: suf.to_vec(),
            }
        }

        pub fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            decrypt(self.cipher, &self.e.key, Some(&self.iv), &input)
        }

        pub fn is_admin(&mut self, input: &[u8]) -> Option<usize> {
            let pat = b";admin=true;";
            input.windows(pat.len()).position(|window| window == pat)
        }

        pub fn has_admin(&mut self, input: &[u8]) -> bool {
            match self.decrypt(input) {
                Err(..) => false,
                Ok(plain) => self.is_admin(&plain).is_some(),
            }
        }
    }

    impl Encrypter for UnknownEncrypterChall16 {
        // AES-128-CBC(pre || attacker-controlled || post, random-key)
        fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let escaped = str::from_utf8(input)
                .unwrap() // FIXME
                .replace('=', "%26")
                .replace(';', "%3B");

            let padded = [&self.pre, escaped.as_bytes(), &self.suf].concat();
            encrypt(self.cipher, &self.e.key, Some(&self.iv), &padded)
        }
    }

    ///! Previous prefix size detection routines actually detect the noise
    ///! length (prefix + suffix). Here we increase the input pad until we find
    ///! an additional identical block. Then we know prefix =
    ///! blk_eq * blk_size - pad_len.
    pub fn detect_prefix_size(enc: &mut dyn Encrypter, blk_size: usize) -> usize {
        let mut enc_prev = enc.encrypt(&[]).unwrap();
        let mut blk_eq = 0;
        let mut pre_len = 0;
        for i in 1..=blk_size {
            let enc_cur = enc.encrypt(&vec![b'A'; i]).unwrap();
            for j in blk_eq..enc_prev.len() / blk_size {
                let blk0 = &enc_prev[blk_size * j..blk_size * (j + 1)];
                let blk1 = &enc_cur[blk_size * j..blk_size * (j + 1)];
                if blk0 == blk1 {
                    blk_eq += 1;
                    pre_len = blk_eq * blk_size - i + 1;
                    if i > 1 {
                        return pre_len;
                    }
                    continue;
                }
            }
            enc_prev = enc_cur;
        }
        pre_len
    }

    #[test]
    fn test_detect_prefix_size() {
        let aes_cbc: Cipher = Cipher::aes_128_cbc();

        let mut unknown1 = UnknownEncrypterChall16::build(aes_cbc, b"", b"1234");
        let blk_size_expected = 16;

        let (blk_size, _) = detect_blk_size(&mut unknown1).unwrap();
        assert_eq!(blk_size, blk_size_expected);

        let pre_len = detect_prefix_size(&mut unknown1, blk_size);
        assert_eq!(pre_len, unknown1.pre.len());

        let mut unknown2 = UnknownEncrypterChall16::build(aes_cbc, &[b'A'; 15], b"ending");
        assert_eq!(
            detect_prefix_size(&mut unknown2, blk_size_expected),
            unknown2.pre.len()
        );

        let mut unknown3 = UnknownEncrypterChall16::build(aes_cbc, &[b'A'; 17], b"ending");
        assert_eq!(
            detect_prefix_size(&mut unknown3, blk_size_expected),
            unknown3.pre.len()
        );

        let mut unknown4 = UnknownEncrypterChall16::build(aes_cbc, &[b'A'; 49], b"ending");
        assert_eq!(
            detect_prefix_size(&mut unknown4, blk_size_expected),
            unknown4.pre.len()
        );
    }

    #[test]
    fn test_cbc_bitflip() {
        let mut unknown = UnknownEncrypterChall16::new(Cipher::aes_128_cbc());
        let blk_size_expected = 16;

        let (blk_size, _noise_len) = detect_blk_size(&mut unknown).unwrap();
        assert_eq!(blk_size, blk_size_expected);

        let pre_len = detect_prefix_size(&mut unknown, blk_size);
        assert_eq!(pre_len, unknown.pre.len());

        let empty = unknown.encrypt(&[]).unwrap();
        assert!(!unknown.has_admin(&empty));

        let attempt1 = unknown.encrypt(b";admin=true;").unwrap();
        assert!(!unknown.has_admin(&attempt1));

        /*
        The plan is to:
        - inject the pattern at block boundary, so we know the encrypted block
        - in the previous encrypted block, xor bits in the bytes corresponding
          to the '?' (0b111111) in the next block, in order to obtain ';' (0b111011) or
          '=' (0b111101)
         */
        let pat = b"?admin?true?";

        let pad = vec![b'A'; blk_size - pre_len % blk_size];
        let pad_len = pad.len();
        let padded = [pad, pat.to_vec()].concat();
        let mut forged = unknown.encrypt(&padded).unwrap();
        let blk_target = pre_len + pad_len - blk_size;
        forged[blk_target + 0] ^= 4;
        forged[blk_target + 6] ^= 2;
        forged[blk_target + 11] ^= 4;
        assert!(unknown.has_admin(&forged));
    }
}
