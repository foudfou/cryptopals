#[cfg(test)]
mod tests {
    use openssl::symm::Cipher;

    use set2::chall12::tests::Encrypter;
    use set2::chall16::tests::UnknownEncrypterChall16;

    fn ctr_detect_prefix_size(enc: &mut dyn Encrypter) -> usize {
        let enc_init = enc.encrypt(&[]).unwrap();
        let enc_a = enc.encrypt(&vec![b'A']).unwrap();
        // We need to try another byte in case the suffix begins with 'A'.
        let enc_b = enc.encrypt(&vec![b'B']).unwrap();

        fn count_identical_bytes(b1: &[u8], b2: &[u8]) -> usize {
            b1.iter().zip(b2.iter()).fold(
                0usize,
                |acc, (&ca, &cb)| if ca == cb { acc + 1 } else { acc },
            )
        }

        let cmp_a = count_identical_bytes(&enc_init, &enc_a);
        let cmp_b = count_identical_bytes(&enc_init, &enc_b);

        if cmp_a == cmp_b {
            cmp_a - 1
        } else {
            cmp_a
        }
    }

    #[test]
    fn test_ctr_bitflip() {
        //! We can't directly use test_cbc_bitflip() as the ciphers have
        //! different properties. Especially we can't re-use
        //! chall14::detect_blk_size() as it's based on padding which CTR
        //! doesn't have.

        let iv = [0u8; 16];
        let mut unknown = UnknownEncrypterChall16::new(Cipher::aes_128_ctr(), iv);

        let empty = unknown.encrypt(&[]).unwrap();
        assert!(!unknown.has_admin(&empty));

        let attempt1 = unknown.encrypt(b";admin=true;").unwrap();
        assert!(!unknown.has_admin(&attempt1));

        let pre_len = ctr_detect_prefix_size(&mut unknown);
        assert_eq!(pre_len, unknown.pre.len());

        // Compared to CBC we don't need to inject at blk boundary: it's
        // sufficient to know the prefix length.
        let pat = b"?admin?true?";
        let mut injected = unknown.encrypt(pat).unwrap();
        injected[pre_len + 0] ^= 4;
        injected[pre_len + 6] ^= 2;
        injected[pre_len + 11] ^= 4;
        assert!(unknown.has_admin(&injected));
    }
}
