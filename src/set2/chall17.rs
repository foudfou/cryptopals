#[cfg(test)]
mod tests {
    use openssl::symm::{decrypt, encrypt, Cipher};
    use rand::prelude::*;

    use crate::b64;
    use crate::pkcs;
    use crate::set2::chall12::tests::{Encrypter, UnknownEncrypter};
    use crate::set2::chall14::tests::detect_blk_size;

    struct UnknownEncrypterChall17 {
        e: UnknownEncrypter,
        iv: [u8; 16],
        // For testing purpose.
        secret: Vec<u8>,
    }

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

        fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            decrypt(Cipher::aes_128_cbc(), &self.e.key, Some(&self.iv), &input)
        }

        fn cypher(&mut self) -> Result<(Vec<u8>, Vec<u8>), openssl::error::ErrorStack> {
            let rand_str = [
                "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
            ];

            let rand_str_idx = self.e.rng.gen_range(0..rand_str.len());
            self.secret = b64::decode(rand_str[rand_str_idx].as_bytes()).unwrap();

            let cypher = self.encrypt(&self.secret.clone())?;
            Ok((cypher, self.iv.to_vec()))
        }
    }

    impl Encrypter for UnknownEncrypterChall17 {
        fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            encrypt(Cipher::aes_128_cbc(), &self.e.key, Some(&self.iv), &input)
        }
    }

    /** Attempts to decrypt a CBC block, given the preceding block.

    Relies on 2 properties: 1. decryption of a block only depends on the
    previous encrypted block, 2. decryption of a block only works for a correct
    padding.

    How ? First target the last byte of block C_n. Attempt to decrypt X || C_n,
    where X is just a forged block, for all possible last byte (0..256). This
    should work for at least one byte: the one makes the last byte of C_n
    decrypt to 0x01, a valid padding. X ⊕ P_int == 0x01, P_int being the plain
    before xor with the previous cypher block. We also know P_n = P_int ⊕
    C_n-1. Since we have C_n-1, we can get P_n.

    For the last byte though, there might be an ambiguity: the decrytion may
    have succeeded either because the underlying plain byte is 0x01 or any
    other valid padding value, depending on the second-to-last byte. This is
    why we must validate our assumption that it's a 0x01 by attempting a second
    decryption with a temporarily altered second-to-last byte.

    Then we can iterate on the second-to-last byte, trying to find the byte
    corresponding to a valid padding (0x02). We thus must setting the last byte
    of X = P_int ⊕ 0x01.
     */
    fn cbc_padding_oracle_blk(enc: &mut UnknownEncrypterChall17, iv: &[u8], blk: &[u8]) -> Vec<u8> {
        let blk_len = blk.len();
        let mut forged = [vec![0u8; blk_len], blk.to_vec()].concat();
        let mut plain_int = vec![0u8; blk_len];
        let mut plain = vec![0u8; blk_len];
        for i in (0..blk_len).rev() {
            let pad = (blk_len - i) as u8;

            for b in 0..=255 {
                forged[i] = b;
                if enc.decrypt(&forged).is_ok() {
                    // For the last byte, we either have plain == 1 or some
                    // valid padding. To distinguish we must retry with an
                    // altered second-to-last byte.
                    if pad == 1 {
                        forged[i - 1] ^= 1;
                        if enc.decrypt(&forged).is_err() {
                            forged[i - 1] ^= 1;
                            continue;
                        }
                    }

                    // X ⊕ P_int == 0x01
                    plain_int[i] = b ^ pad;
                    // P_n = P_int ⊕ C_n-1
                    plain[i] = plain_int[i] ^ iv[i];
                    //println!("pad={} b={} plain={}", pad, b, plain[i]);
                    break;
                }
            }

            for j in i..blk_len {
                forged[j] = plain_int[j] ^ (pad + 1);
            }
        }
        plain
    }

    const BLK_SIZE: usize = 16;

    #[test]
    fn test_blk_size() {
        let mut unknown = UnknownEncrypterChall17::new();
        let (blk_size, _) = detect_blk_size(&mut unknown).unwrap();
        assert_eq!(blk_size, BLK_SIZE);
    }

    #[test]
    fn test_cbc_padding_oracle_blk() {
        for _ in 0..200 {
            let mut unknown = UnknownEncrypterChall17::new();

            let (cypher, _iv) = unknown.cypher().unwrap();
            let cypher_len = cypher.len();
            let plain = cbc_padding_oracle_blk(
                &mut unknown,
                &cypher[cypher_len - 2 * BLK_SIZE..cypher_len - BLK_SIZE],
                &cypher[cypher_len - BLK_SIZE..cypher_len],
            );

            let sec_len = unknown.secret.len();
            let secret = &unknown.secret[sec_len - (unknown.secret.len() % BLK_SIZE)..sec_len];

            debug_assert!(
                plain.starts_with(&secret),
                "\ncypher={:?}\nplain={:?}\nsecret={:?}",
                &cypher[cypher_len - 2 * BLK_SIZE..cypher_len],
                plain,
                secret
            );
        }
    }

    fn cbc_padding_oracle(
        unknown: &mut UnknownEncrypterChall17,
        iv: &[u8],
        cypher: &[u8],
        blk_size: usize,
    ) -> Vec<u8> {
        let cypher_with_iv: Vec<u8> = [iv, cypher].concat();
        let blks: Vec<&[u8]> = cypher_with_iv.chunks(blk_size).collect();
        let mut plain: Vec<u8> = vec![];
        for window in blks.windows(2) {
            plain.extend_from_slice(&cbc_padding_oracle_blk(unknown, window[0], window[1]))
        }
        plain
    }

    #[test]
    fn test_cbc_padding_oracle() {
        for _ in 0..200 {
            let mut unknown = UnknownEncrypterChall17::new();

            let (cypher, iv) = unknown.cypher().unwrap();
            let plain = cbc_padding_oracle(&mut unknown, &iv, &cypher, BLK_SIZE);
            // debug_assert!(plain.starts_with(&unknown.secret),
            //               "\nplain={:?}\nsecret={:?}", plain, unknown.secret);
            let unpadded = pkcs::pkcs7_unpad(&plain).unwrap();
            assert_eq!(unknown.secret, unpadded);
        }
    }
}
