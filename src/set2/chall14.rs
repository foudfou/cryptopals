#[cfg(test)]
pub mod tests {
    use rand::prelude::*;

    use aes;
    use set2::chall12::tests::{ecb_oracle, Encrypter, UnknownEncrypter};

    struct UnknownWrapEncrypter {
        e: UnknownEncrypter,
        pre: Vec<u8>,
    }

    impl UnknownWrapEncrypter {
        fn new() -> UnknownWrapEncrypter {
            let mut enc = UnknownEncrypter::new();
            let mut pre = [0u8; 32];
            let pre_len = enc.rng.gen_range(1, 33);
            enc.rng.fill_bytes(&mut pre[..pre_len]);

            UnknownWrapEncrypter {
                e: enc,
                pre: pre[..pre_len].to_vec(),
            }
        }
    }

    impl Encrypter for UnknownWrapEncrypter {
        // AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
        fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let padded = [&self.pre, input].concat();
            self.e.encrypt(&padded)
        }
    }

    pub fn detect_blk_size(enc: &mut dyn Encrypter) -> Option<(usize, usize)> {
        let len_init = enc.encrypt(&[]).unwrap().len();
        let len_prev = len_init;
        for i in 1..=256 {
            let input = vec![b'A'; i];
            let len_cur = enc.encrypt(&input).unwrap().len();
            if len_prev != len_cur {
                return Some((len_cur - len_prev, len_init - i));
            }
        }
        None
    }

    fn detect_prefix_size(enc: &mut UnknownWrapEncrypter, blk_size: usize) -> Option<usize> {
        for i in 0..=blk_size {
            let input = vec![b'A'; i + 2 * blk_size];
            let enc = enc.encrypt(&input).unwrap();
            let blks: Vec<&[u8]> = enc.chunks(blk_size).collect();
            for j in 0..blks.len() - 1 {
                if blks[j] == blks[j + 1] {
                    return Some(j * blk_size - i);
                }
            }
        }
        None
    }

    #[test]
    fn test_ecb_oracle() {
        for _ in 0..5 {
            let mut unknown = UnknownWrapEncrypter::new();
            let blk_size_expected = 16;

            let (blk_size, _pad_len) = detect_blk_size(&mut unknown).unwrap();
            assert_eq!(blk_size, blk_size_expected);
            let encrypted = unknown.encrypt(&mut vec![b'A'; 4 * blk_size]).unwrap();
            assert!(aes::detect_ecb(&encrypted, blk_size));

            // We need first to assess that the prefix size is fixed.
            let mut pre_len = detect_prefix_size(&mut unknown, blk_size_expected).unwrap();
            assert_eq!(pre_len, unknown.pre.len());
            let mut pre_len_prev = pre_len;
            for _ in 0..10 {
                pre_len = detect_prefix_size(&mut unknown, blk_size_expected).unwrap();
                assert_eq!(pre_len, pre_len_prev);
                pre_len_prev = pre_len;
            }

            let clear = ecb_oracle(&mut unknown, blk_size_expected, 138, pre_len);
            assert_eq!(clear, unknown.e.secret.unwrap());
        }
    }
}
