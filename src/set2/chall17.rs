#[cfg(test)]
mod tests {
    use openssl::symm::{decrypt, encrypt, Cipher};
    use rand::prelude::*;

    use b64;
    use pkcs;
    use set2::chall12::tests::{Encrypter,UnknownEncrypter};

    struct UnknownEncrypterChall17 { e: UnknownEncrypter, iv: [u8; 16], secret: Vec<u8>, }

    impl UnknownEncrypterChall17 {

        fn new() -> UnknownEncrypterChall17 {
            let mut enc = UnknownEncrypter::new();
            let mut iv = [0u8; 16];
            enc.rng.fill_bytes(&mut iv);

            UnknownEncrypterChall17 {
                e: enc,
                iv: iv,
                secret: vec![],
            }
        }

        fn decrypt(&mut self, input: &[u8])
                   -> Result<Vec<u8>, openssl::error::ErrorStack> {
            decrypt(Cipher::aes_128_cbc(), &self.e.key, Some(&self.iv), &input)
        }

    }

    impl Encrypter for UnknownEncrypterChall17 {
        ///! Although instructions require encrypt() to return the iv also, we
        ///! prefer to stick with our Encrypter trait for now. Consumers can
        ///! get the iv from the UnknownEncrypterChall17 struct.
        fn encrypt(&mut self, _input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let rand_str = [
                "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                // "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                // "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                // "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                // "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                // "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                // "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                // "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                // "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                // "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
            ];

            let rand_str_idx = self.e.rng.gen_range(0, rand_str.len());
            self.secret = b64::decode(rand_str[rand_str_idx].as_bytes()).unwrap();

            encrypt(Cipher::aes_128_cbc(), &self.e.key, Some(&self.iv), &self.secret)
        }
    }

    ///! FIXME explain
    fn cbc_padding_oracle_blk(enc: &mut UnknownEncrypterChall17,
                              iv: &[u8],
                              blk: &[u8])
                              -> Vec<u8> {
        let blk_len = blk.len();
        let mut forged = [vec![0u8; blk_len], blk.to_vec()].concat();
        let mut plain_int = vec![0u8; blk_len];
        let mut plain = vec![0u8; blk_len];
        for i in (0..blk_len).rev() {
            let pad = (blk_len - i) as u8;
            for b in 0..=255 {
                forged[i] = b;
                if enc.decrypt(&forged).is_ok() {
                    // X ⊕ P_int == 0x01
                    plain_int[i] = b ^ pad;
                    // P_n = P_int ⊕ C_n-1
                    plain[i] = plain_int[i] ^ iv[i];
                    //println!("i={} b={} plain={}", pad, b, plain[i]);
                    break;
                }
            }

            for j in i..blk_len {
                forged[j] = plain_int[j] ^ (pad + 1);
            }
        }
        plain
    }

    fn cbc_padding_oracle(unknown: &mut UnknownEncrypterChall17,
                          cypher: &[u8],
                          blk_size: usize) -> Vec<u8>
    {
        let mut blks: Vec<&[u8]> = cypher.chunks(blk_size).collect();
        let iv = unknown.iv.clone();
        blks.insert(0, &iv);
        let all: Vec<Vec<u8>> =
            blks.windows(2).rev().map(|window| {
            cbc_padding_oracle_blk(unknown, window[0], window[1])
        }).rev().collect();
        all.concat()
    }

    #[test]
    fn test_cbc_padding_oracle() {
        for _ in 0..500 {
            let mut unknown = UnknownEncrypterChall17::new();
            let blk_size_assumed = 16; // FIXME

            let cypher = unknown.encrypt(&[]).unwrap();
            let plain = cbc_padding_oracle(&mut unknown, &cypher, blk_size_assumed);
            let unpadded = pkcs::pkcs7_unpad(&plain).unwrap();
            assert_eq!(unknown.secret, unpadded);
        }
    }

}
