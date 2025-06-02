#[cfg(test)]
mod tests {
    // 2025-05-29 rug uses gmp-mpfr-sys which fails to compile. Could also use
    // openssl::bn::BigNum.
    use num::Num;
    use num_bigint::{BigUint, RandBigInt, ToBigUint};

    // https://github.com/rust-num/num-bigint/blob/master/tests/modpow.rs
    static P2: &str = "\
    ffffffff_ffffffff_c90fdaa2_2168c234_c4c6628b_80dc1cd1\
    29024e08_8a67cc74_020bbea6_3b139b22_514a0879_8e3404dd\
    ef9519b3_cd3a431b_302b0a6d_f25f1437_4fe1356d_6d51c245\
    e485b576_625e7ec6_f44c42e9_a637ed6b_0bff5cb6_f406b7ed\
    ee386bfb_5a899fa5_ae9f2411_7c4b1fe6_49286651_ece45b3d\
    c2007cb8_a163bf05_98da4836_1c55d39a_69163fa8_fd24cf5f\
    83655d23_dca3ad96_1c62f356_208552bb_9ed52907_7096966d\
    670c354e_4abc9804_f1746c08_ca237327_ffffffff_ffffffff";

    #[test]
    fn test_diffie_hellman() {
        // As per instructions, rather than actually *implementing* DH, we
        // *apply* it.
        let p = 37.to_biguint().unwrap();
        let g = 5.to_biguint().unwrap();

        let mut rng = rand::thread_rng();

        let low = 16.to_biguint().unwrap();
        let high = 128.to_biguint().unwrap();

        let a = rng.gen_biguint_range(&low, &high);
        // A = (g**a) % p, Alice pub key
        let ka = g.clone().modpow(&a, &p);

        // B = (g**b) % p, Bob pub key
        let b = rng.gen_biguint_range(&low, &high);
        let kb = g.clone().modpow(&b, &p);

        // K = B**a % p = A**b % p, secret shared key
        let sa = kb.clone().modpow(&a, &p);
        let sb = ka.clone().modpow(&b, &p);
        assert_eq!(sa, sb);

        // Same but with more realistic p
        let p2 = BigUint::from_str_radix(P2, 16).unwrap();
        let g2 = 2.to_biguint().unwrap();

        let ka2 = g2.clone().modpow(&a, &p2);
        let kb2 = g2.clone().modpow(&b, &p2);
        let sa2 = kb2.clone().modpow(&a, &p2);
        let sb2 = ka2.clone().modpow(&b, &p2);
        // println!("a={} b={} sa2={}, sb2={}", a, b, sa2, sb2);
        assert_eq!(sa2, sb2);

        use crate::md4::md4;

        // Create 128 bits key by hashing secret
        let sa2_vec = sa2.to_bytes_be();
        let sb2_vec = sb2.to_bytes_be();
        assert!(sa2_vec.len() > 128 / 8);
        let sa2_bytes = sa2_vec.as_slice();
        let sa2_key = md4(sa2_bytes);
        let sb2_bytes = sb2_vec.as_slice();
        let sb2_key = md4(sb2_bytes);
        assert_eq!(sa2_key, sb2_key);
    }
}
