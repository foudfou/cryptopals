#[cfg(test)]
mod tests {
    use num_bigint::{BigUint, ToBigUint};
    use openssl::symm::{decrypt, encrypt, Cipher};

    use crate::sha::sha1;

    #[test]
    fn test_diffie_hellman_ok() {
        // Generating bigint primes is… maybe not so straightforward. We could
        // use crypto-bigint and crypto-primes crates to generate some later,
        // but we'll just pick a known one for now.
        let p = BigUint::parse_bytes(
            b"\
            1701543668286650795033156353595663906261538600974101176736984145\
            4266335544470989396657175007332269271227766697131334816084183599\
            1041384679700511912064982526249529596585220499141442747333138443\
            7450823957119572310403415995084907205843450441456787169643269098\
            52653412051765274781142172235546768485104821112642811",
            10,
        )
        .unwrap();
        let g = 2.to_biguint().unwrap();

        // A->B: Send `"p"`, `"g"`, `"A"`
        //
        let a = 56.to_biguint().unwrap();
        let ka = g.clone().modpow(&a, &p);

        // B->A: Send `"B"`
        //
        let b = 122.to_biguint().unwrap();
        let kb = g.clone().modpow(&b, &p);
        // Bob computes K
        let sb = ka.clone().modpow(&b, &p);

        // A->B: Send `AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv`
        //
        let sa = kb.clone().modpow(&a, &p);
        let sa_vec = sa.to_bytes_be();
        assert!(sa_vec.len() > 128 / 8);
        let sa_bytes = sa_vec.as_slice();
        let sa_sha1 = sha1(sa_bytes);
        let sa_hash = &sa_sha1[0..16];
        // println!("s_hash={:x?}", s_hash);
        let msg_a = b"Alice's message to Bob";
        let iv_a = b"\
        \x00\x01\x02\x03\x04\x05\x06\x07\
        \x00\x01\x02\x03\x04\x05\x06\x07";
        let cipher_a = encrypt(Cipher::aes_128_cbc(), sa_hash, Some(iv_a), msg_a).unwrap();

        // B->A: Send `AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv`
        //
        let clear_a = decrypt(Cipher::aes_128_cbc(), sa_hash, Some(iv_a), &cipher_a).unwrap();
        assert_eq!(clear_a, msg_a);
        let sb_sha1 = sha1(sb.to_bytes_be().as_slice());
        let sb_hash = &sb_sha1[0..16];
        let msg_b = b"Bob's message to Alice";
        let iv_b = b"\
        \x07\x06\x05\x04\x03\x02\x01\x00\
        \x07\x06\x05\x04\x03\x02\x01\x00";
        let cipher_b = encrypt(Cipher::aes_128_cbc(), sb_hash, Some(iv_b), msg_b).unwrap();

        // (Alice reads Bob's message)
        let clear_b = decrypt(Cipher::aes_128_cbc(), sa_hash, Some(iv_b), &cipher_b).unwrap();
        assert_eq!(clear_b, msg_b);
    }
}
