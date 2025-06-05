#[cfg(test)]
mod tests {
    use num_bigint::{BigUint, ToBigUint};

    use crate::set5::chall36::*;

    fn gen_prime(ksz: u32) -> BigUint {
        use openssl::bn::BigNum;
        let mut bn = BigNum::new().unwrap();
        assert!(bn.generate_prime(ksz as i32, true, None, None).is_ok());
        BigUint::from_bytes_be(&bn.to_vec())
    }

    // c = m**e % n
    fn encrypt(m: &[u8], e: &BigUint, n: &BigUint) -> Vec<u8> {
        BigUint::from_bytes_be(m).modpow(e, n).to_bytes_be()
    }

    // m = c**d % n
    fn decrypt(c: &[u8], d: &BigUint, n: &BigUint) -> Vec<u8> {
        BigUint::from_bytes_be(c).modpow(d, n).to_bytes_be()
    }

    #[test]
    fn test_rsa_impl() {
        let one = BigUint::from(1_u32);

        let p = gen_prime(KEY_SIZE);
        let q = gen_prime(KEY_SIZE);
        // "modulus" also key length
        let n = &p * &q;
        // "totient", only for keygen
        let et = (p - &one) * (q - &one);
        // 3 is the smallest/fastest value. The otherwise most commonly chosen
        // value is 216 + 1 = 65537.
        let e = 3.to_biguint().unwrap(); // to encrypt

        let d = e.modinv(&et).unwrap(); // to decrypt
        assert_eq!(
            BigUint::from(17_u32)
                .modinv(&BigUint::from(3120_u32))
                .unwrap(),
            BigUint::from(2753_u32)
        );

        // Public key = [e, n]. Private key = [d, n].

        let message: &[u8] = &[42];
        let cipher = encrypt(message, &e, &n);
        let clear = decrypt(&cipher, &d, &n);
        assert_eq!(clear, message);

        let message = b"FOUDIL WAS HERE";
        let cipher = encrypt(message, &e, &n);
        let clear = decrypt(&cipher, &d, &n);
        assert_eq!(clear, message);
    }
}
