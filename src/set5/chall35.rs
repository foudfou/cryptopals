#[cfg(test)]
mod tests {
    // DH with negotiated groups, malicious "g" parameters
    //
    // Same protocol as in chall33, except additional initial group
    // negotiation: A->B: Send "p", "g"; B->A: Send ACK; A->B: Send "A")
    //
    // Reminder:
    // A = (g**a) % p, Alice pub key
    // K = B**a % p = A**b % p, secret shared key
    //
    // For g = 1 (say M sends this to Bob), 1**n = 1. Thus 1 % p = 1 for n>1.
    // I.e. all pub keys = K = 1. NOT IMPLEMENTED
    //
    // For g = p, all pub keys = 0 (p**n % p). Thus K = 0 (0**n % p). NOT
    // IMPLEMENTED
    //
    // For g = p - 1, pub keys = either 1 if n is even or (p - 1) if n is odd
    // (1). Thus K = either 1 (1**b % p) or ((p - 1)**b % p), which in turn is
    // either 1 if b is even or (p -1) if b is odd.
    //
    // Let's review all cases:
    // 1. a even, b even: A=1 B=1 K=1
    // 2. a odd, b even: A=p-1 B=1 Ka=p-1 Kb=1 (similarly when a even b odd)
    // 3. a odd, b odd: A=p-1 B=p-1 Ka=p-1 Kb=p-1
    // M will thus have to detect different cases and re-encrypt messages in
    // case 2.
    //
    // (1) Explanation involves modular arithmetic, which I didn't fully grok.
    // The idea is: g = p - 1 = -1 % p (picture a clock of p units). So
    // g**a % p = (-1 % p)**a = -1**a % p.

    use num_bigint::{BigUint, RandBigInt, ToBigUint};
    use openssl::symm::{decrypt, encrypt, Cipher};

    use crate::sha::sha1;

    // TODO property-testing (proptest?)
    #[test]
    fn test_diffie_hellman_proto_pminusone() {
        let p = BigUint::parse_bytes(
            b"\
            8595358981583354919090196812707113541087577352290988883098221248\
            9194398459954029288929783878717809885936673417996386435081904978\
            35810277773878977282934501",
            10,
        )
        .unwrap();
        let one_biguint = 1.to_biguint().unwrap();
        let g = p.clone() - &one_biguint;

        let mut rng = rand::thread_rng();

        let a = rng.gen_biguint(1024);
        let b = rng.gen_biguint(1024);

        let ka = g.clone().modpow(&a, &p);
        assert!(ka == one_biguint || ka == g);

        // The instructions ("play with 'g'") are not very clear with regard to
        // how M should operate. They also state that tampering parameters (on
        // Alice's system) is not a realistic scenario.
        //
        // For the purpose of this exercise, we'll assume Alice's system has
        // been compromised to use g = p - 1 and M will forward that to B. For
        // both comms with A and B, M uses exponent m=2 so M=1, K=1. Note this
        // completely circumvents cases where a or b are odd.
        let m = &2.to_biguint().unwrap();
        let km = g.clone().modpow(m, &p);
        assert_eq!(km, one_biguint);

        // For clarity maybe, let's do A-M comms first, then M-B.

        // A->M: Send "p", "g"
        // M->A: Send ACK
        // A->M: Send "A"
        //
        let sma = ka.clone().modpow(m, &p);
        assert_eq!(sma, one_biguint);
        // M->A: Send "M"
        //
        let sa = km.clone().modpow(&a, &p);
        assert_eq!(sa, one_biguint);
        // println!("a={} b={}\nka={} sa={}", a, b, ka, sa);

        // M->B: Send "p", "g"
        //
        let kb = g.clone().modpow(&b, &p);
        assert!(kb == one_biguint || kb == g);
        // B->M: Send ACK
        // M->B: Send "M"
        //
        let sb = km.clone().modpow(&b, &p);
        assert_eq!(sb, one_biguint);
        // B->M: Send "B"
        //
        let smb = kb.clone().modpow(&m, &p);
        assert_eq!(smb, one_biguint);

        //
        // Note at this point sa = sma = smb = sb = 1. Pretty much GAME OVER
        //
        let s = &[1];

        // A->B: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
        //
        // A->M: Send cipher_a+iv_a
        //
        let s_hash = &sha1(s)[0..16];
        let msg_a = b"Alice to Bob";
        let iv_a = b"\
        \x00\x01\x02\x03\x04\x05\x06\x07\
        \x00\x01\x02\x03\x04\x05\x06\x07";
        let cipher_a = encrypt(Cipher::aes_128_cbc(), s_hash, Some(iv_a), msg_a).unwrap();
        // M can easily decrypt msg_a as K=1
        let clear_a = decrypt(Cipher::aes_128_cbc(), s_hash, Some(iv_a), &cipher_a).unwrap();
        assert_eq!(clear_a, msg_a);
        // M->B: Send cipher_a+iv_a
        //
        let clear_b = decrypt(Cipher::aes_128_cbc(), s_hash, Some(iv_a), &cipher_a).unwrap();
        assert_eq!(clear_b, msg_a);

        // and so on…

        // B->A: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    }
}
