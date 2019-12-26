#[cfg(test)]
pub mod tests {
    use openssl::symm::{encrypt, Cipher};
    use rand::prelude::*;

    use b64;
    use aes;

    pub trait Encrypter {
        fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack>;
    }

    pub struct UnknownEncrypter {
        pub key: [u8; 16],
        pub secret: Option<Vec<u8>>,
        pub rng: ThreadRng,
    }

    impl UnknownEncrypter {

        pub fn new() -> UnknownEncrypter {
            let mut rng = rand::thread_rng();

            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);

            let secret= b64::decode(
                b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                  YnkK"
            ).unwrap();

            UnknownEncrypter { key: key, secret: Some(secret), rng: rng, }
        }

    }

    impl Encrypter for UnknownEncrypter {
        // AES-128-ECB(your-string || unknown-string, random-key)
        fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let sec = self.secret.as_ref().unwrap();
            let padded = [input, &sec].concat();
            encrypt(Cipher::aes_128_ecb(), &self.key, None, &padded)
        }
    }

    #[test]
    fn test_aes_128_cbc_encrypt() {
        let data = b"Some Crypto Text";
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
        let cipher = encrypt(Cipher::aes_128_cbc(), key, Some(iv), data).unwrap();
        let want = b"\xB4\xB9\xE7\x30\xD6\xD6\xF7\xDE\x77\x3F\x1C\xFF\xB3\x3E\x44\x5A\
                     \x91\xD7\x27\x62\x87\x4D\xFB\x3C\x5E\xC4\x59\x72\x4A\xF4\x7C\xA1";
        assert_eq!(&cipher[..], want);
    }

    #[derive(PartialEq)]
    enum AesMode {ECB, CBC,}

    ///! Encrypts randomly in AES ECB or CBC, with random key, random left and
    ///! right pads.
    fn aes_rand_encrypt(input: &[u8]) -> Result<(Vec<u8>, AesMode), openssl::error::ErrorStack> {
        let mut rng = rand::thread_rng();

        let mut lpad = [0u8; 10];
        let lpad_len = rng.gen_range(5, 11);
        rng.fill_bytes(&mut lpad[..lpad_len]);

        let mut rpad = [0u8; 10];
        let rpad_len = rng.gen_range(5, 11);
        rng.fill_bytes(&mut rpad[..rpad_len]);

        let padded = [&lpad[..lpad_len], input, &rpad[..rpad_len]].concat();

        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);

        let mut iv = [0u8; 16];
        let (mode, cipher, iv) = if rand::random() {
            (AesMode::ECB, Cipher::aes_128_ecb(), None)
        } else {
            rng.fill_bytes(&mut iv);
            (AesMode::CBC, Cipher::aes_128_cbc(), Some(&iv[..]))
        };
        let enc = encrypt(cipher, &key, iv, &padded)?;
        Ok((enc, mode))
    }

    #[test]
    fn test_aes_rand_detect() {
        // We can detect ECB if the input is large enough.
        let input = [b'A'; 48];
        for _ in 0..100 {
            let (aes_128_rand_encoded, aes_mode) = aes_rand_encrypt(&input).unwrap();
            let ecb_detected = aes::detect_ecb(&aes_128_rand_encoded, 16);
            assert_eq!(ecb_detected, aes_mode == AesMode::ECB);
        }
    }

    // We need 2 consecutive identical blocks.
    fn guess_ecb_blk_via_cmp(enc: &mut UnknownEncrypter) -> Option<usize> {
        for bsize in 8..=256 {
            let input = vec![b'A'; 2*bsize];
            let encoded = enc.encrypt(&input).unwrap();
            if &encoded[..bsize] == &encoded[bsize..2*bsize] {
                return Some(bsize)
            }
        }
        None
    }

    // Guess block and secret size. Exploiting PKCS7 padding.
    fn guess_ecb_blk_and_sec(enc: &mut UnknownEncrypter) -> Option<(usize, usize)> {
        let len_init = enc.encrypt(&[]).unwrap().len();
        let len_prev = len_init;
        for i in 1..=256 {
            let input = vec![b'A'; i];
            let len_cur = enc.encrypt(&input).unwrap().len();
            if len_prev != len_cur {
                return Some((len_cur - len_prev, len_init - i))
            }
        }
        None
    }

    ///! Guesses an encrypted text, given an unknown encrypter (ECB with pre-
    ///! and post-noise) by guessing one byte at a time. We can compare a block
    ///! of encrypted AAAU with encrypted AAAX, U being the first unknown byte
    ///! of the clear text, X being all possible bytes. Then we can try AAKU
    ///! with AAKX, where K is the known guessed byte. As so on.
    pub fn ecb_oracle(unknown: &mut dyn Encrypter,
                      blk_size: usize,
                      sec_size: usize,
                      pre_len: usize,
    ) -> Vec<u8> {
        let mut clear: Vec<u8> = Vec::new();

        let pre_pad = vec![b'A'; blk_size - pre_len % blk_size];
        let empty_enc = unknown.encrypt(&pre_pad).unwrap();

        let blk_start = (pre_len + pre_pad.len()) / blk_size;
        'blocks: for j in blk_start..empty_enc.len()/blk_size {
            for i in 1..=blk_size {
                let pad = vec![b'A'; pre_pad.len()+blk_size-i];
                let pad_enc = unknown.encrypt(&pad).unwrap();

                let mut found = false;
                for b in 0u8..=255 {
                    let mut input = pad.clone();
                    input.append(&mut clear.clone());
                    input.push(b);
                    let enc = unknown.encrypt(&input).unwrap();
                    let blk = enc[j*blk_size..(j+1)*blk_size].to_vec();
                    let pad_blk = pad_enc[j*blk_size..(j+1)*blk_size].to_vec();
                    if blk == pad_blk {
                        found = true;
                        clear.push(b);
                        break;
                    }
                }

                if !found { panic!("Byte not found at block={}, byte={}", j, i); }
                if clear.len() == sec_size { break 'blocks; }
            }
        }

        clear
    }

    #[test]
    fn test_ecb_oracle() {
        let mut unknown = UnknownEncrypter::new();
        let (blk_size, secret_size) = guess_ecb_blk_and_sec(&mut unknown).unwrap();
        assert_eq!(blk_size, 16);
        assert_eq!(blk_size, guess_ecb_blk_via_cmp(&mut unknown).unwrap());
        assert_eq!(secret_size, 138);

        let encrypted = unknown.encrypt(&mut vec![b'A'; 2*blk_size]).unwrap();
        assert!(aes::detect_ecb(&encrypted, blk_size));

        let clear = ecb_oracle(&mut unknown, blk_size, secret_size, 0);

        // println!("-> {:?}", clear.iter().map(|&c| c as char).collect::<String>());
        assert_eq!(clear, unknown.secret.unwrap());
    }

}
