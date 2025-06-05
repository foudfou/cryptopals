use num_bigint::{BigUint, RandBigInt, ToBigUint};
use rand::prelude::*;

use crate::hmac::hmac;
use crate::sha::{sha256, sha256_for_hmac};

pub const KEY_SIZE: u32 = 2048;

// Fixed to speed up tests
pub const N: &[u8] = b"\
            00d5137edacb404e7a327a71a9e25fbbc9de87d24814b488d88eb57cfff9\
            00ae7de593647094fa4382179c9228d9e68504bcace9d2fd73814316b5a5\
            196b880fdde537f003362f5673e69cc9de6f74e1e4394728bfc2c9297e5c\
            d994dd418a7b2e99b5fff5da52c4572d65604b5c2f616dece63d5b389196\
            1787b445a4fdbab5ab4ba93f2fce5dcc036d75bf98e62774090779ac9989\
            fa469c9017fa64dafc864329a826fa967459ed35abaf07caab8600129766\
            7a29586e04871f4e4c1d7619fe3a77ff71865b79d4500eca7f2c8e7f8d1c\
            f71075b1c497dc35d0909f157372f645952cd95bcf2fcd852993491c9bca\
            43cdc1915021a7c2c4342a088d013541ef";

pub fn srp_proto(ka_inject: Option<BigUint>, sc_inject: Option<BigUint>) {
    // See more detailed SRP description at the end of this file or on
    // Wikipedia. Note ALL ARITHMETIC IS DONE MODULO N.
    //
    // Compared to DH, SRP is an authentication protocol. I.e. The main
    // ideas are:
    // - S initially only stores the password verifier, based on a hash of
    //   the salted password (user-provided). I.e. stolen server data can
    //   not be used to impersonate.
    // - C and S derive a shared session key (similar to DH), based on
    //   ephemeral keys (a, b)
    // - C and S finally prove to each other that their keys match by
    //   sending HMACs of K with parameters. Here only S does that.

    // C & S
    //     Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    // println!("n={:02x?}", &n.to_bytes_be());

    //
    // openssl dhparam -text 2048 # "2048 bit long safe prime"
    // openssl prime -generate -bits 1024 -safe -hex
    //
    // use openssl::bn::BigNum;
    // let mut bn = BigNum::new().unwrap();
    // assert!(bn.generate_prime(KEY_SIZE as i32, true, None, None).is_ok());
    // let n = BigUint::from_bytes_be(&bn.to_vec());
    //
    let n = BigUint::parse_bytes(N, 16).unwrap();

    let g = 2.to_biguint().unwrap();
    let k = 3.to_biguint().unwrap();
    // "Only" used for user lookup by S
    let _username = b"fou@d.il";
    let password = b"123456";

    // S
    //         Generate salt as random integer
    // Some descriptions (stanford, wikipedia) have the client generating
    // the salt.
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 64];
    rng.fill_bytes(&mut salt);
    //         Generate string xH=SHA256(salt|password)
    let saltpass = [&salt[..], &password[..]];
    let xh = sha256(&saltpass);
    //         Convert xH to integer x somehow (put 0x on hexdigest)
    let x = BigUint::from_bytes_be(&xh);
    //         Generate v=g**x % N
    let v = g.clone().modpow(&x, &n);
    //         Save everything but x, xH

    // C->S
    //     Send I, A=g**a % N (a la Diffie Hellman)
    let a = rng.gen_biguint(KEY_SIZE as u64);
    // println!("a={}", a);
    let ka = match ka_inject {
        None => g.clone().modpow(&a, &n),
        Some(kai) => kai,
    };

    // S->C
    //     Send salt, B=kv + g**b % N
    let b = rng.gen_biguint(KEY_SIZE as u64);
    let kb = &k * v.clone() + g.clone().modpow(&b, &n);
    // println!("b={}", b);

    // S, C
    //     Compute string uH = SHA256(A|B), u = integer of uH
    let ab = [&ka.to_bytes_be()[..], &kb.to_bytes_be()[..]];
    let uh = sha256(&ab);
    // println!("ka={:02x?}\nkb={:02x?}", ka.to_bytes_be(), kb.to_bytes_be());
    // println!("u={:02x?}", uh);
    let u = BigUint::from_bytes_be(&uh);

    // C
    //         Generate string xH=SHA256(salt|password)
    //         Convert xH to integer x somehow (put 0x on hexdigest)
    // Actually C did that already earlier
    //         Generate S = (B - k * g**x)**(a + u * x) % N
    let sc = match sc_inject {
        // Expert version inspired by
        // https://github.com/RustCrypto/PAKEs/blob/master/srp/src/client.rs
        // let sc_base = (&k * &g.modpow(&x, &n)) % &n;
        // let sc_base = ((&kb + &n) - &sc_base) % &n; // Adding N to B in case B < base.
        // let sc2 = sc_base.modpow(&(&a + &u * &x), &n);
        // println!("sc2={:02x?}", &sc2);
        None => (&kb - (&k * &g.modpow(&x, &n))).modpow(&(&a + &u * &x), &n),
        Some(sci) => sci,
    };
    //         Generate K = SHA256(S)
    let kc = sha256(&[&sc.to_bytes_be()]);

    // S
    //         Generate S = (A * v**u) ** b % N
    let ss_base = (ka * &v.modpow(&u, &n)) % &n;
    let ss = ss_base.modpow(&b, &n);
    //         Generate K = SHA256(S)
    let ks = sha256(&[&ss.to_bytes_be()]);
    assert_eq!(kc, ks);
    // println!("sc={:02x?}\nss={:02x?}", &sc, &ss);
    // println!("kc={:02x?}\nks={:02x?}", &kc, &ks);

    // C->S
    //     Send HMAC-SHA256(K, salt)
    let hmac_c = hmac(&salt, &kc, sha256_for_hmac, 32);

    // S->C
    //     Send "OK" if HMAC-SHA256(K, salt) validates
    let hmac_s = hmac(&salt, &ks, sha256_for_hmac, 32);
    assert_eq!(hmac_c, hmac_s);
}

#[cfg(test)]
mod tests {
    use crate::set5::chall36::*;

    #[test]
    fn test_srp_ok() {
        srp_proto(None, None);
    }
}

// SRP description from http://srp.stanford.edu/design.html
//
//  The following is a description of SRP-6 and 6a, the latest versions of SRP:
//
//   N    A large safe prime (N = 2q+1, where q is prime)
//        All arithmetic is done modulo N.
//   g    A generator modulo N
//   k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
//   s    User's salt
//   I    Username
//   p    Cleartext Password
//   H()  One-way hash function
//   ^    (Modular) Exponentiation
//   u    Random scrambling parameter
//   a,b  Secret ephemeral values
//   A,B  Public ephemeral values
//   x    Private key (derived from p and s)
//   v    Password verifier
//
// The host stores passwords using the following formula:
//
//   x = H(s, p)               (s is chosen randomly)
//   v = g^x                   (computes password verifier)
//
// The host then keeps {I, s, v} in its password database. The authentication protocol itself goes as follows:
//
// User -> Host:  I, A = g^a                  (identifies self, a = random number)
// Host -> User:  s, B = kv + g^b             (sends salt, b = random number)
//
//         Both:  u = H(A, B)
//
//         User:  x = H(s, p)                 (user enters password)
//         User:  S = (B - kg^x) ^ (a + ux)   (computes session key)
//         User:  K = H(S)
//
//         Host:  S = (Av^u) ^ b              (computes session key)
//         Host:  K = H(S)
//
// Now the two parties have a shared, strong session key K. To complete authentication, they need to prove to each other that their keys match. One possible way:
//
// User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
// Host -> User:  H(A, M, K)
