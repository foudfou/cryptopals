#[cfg(test)]
mod tests {
    use num_bigint::{BigUint, RandBigInt, ToBigUint};
    use rand::prelude::*;

    use crate::hmac::hmac;

    fn sha256(bufs: &[&[u8]]) -> [u8; 32] {
        let mut hasher = openssl::sha::Sha256::new();
        for buf in bufs {
            hasher.update(buf);
        }
        hasher.finish()
    }

    fn sha256_for_hmac(buf: &[u8]) -> Vec<u8> {
        sha256(&[buf]).to_vec()
    }

    #[test]
    fn test_sha256() {
        use crate::b64::hex2bytes;

        let i = &hex2bytes(
            "\
c15494230bdd6746cd5ad01ed08267243c8c474721324386ad65af98d7274666\
48a70153b22677b740befb6b14b9360bc1b0e0b129567a8594b301317c9bb5a4\
d276123f56ee70c5790fb28a8e2b5788d9304a763a473c0cf811519cf00f5e1d\
bf70493a91ecfce9f4cdabe9f9c89dac9c1e774a2030e577767bf78fa5b01926\
ecf921e67a5595ae0e674ab1cfcf545cdbad5f3229550ea204fb007e42ae3a0e\
f80a9629439fd6a903ddefadc4e2a5b948d8b90efbd02c4fc87fad6295428e03\
0883c2052a0d0c7e59ced65198cdac3ced50b55a0e5202e8355f46fb83aa7fc9\
2560b999aad8664dc78ab05afe222e2fa23161e9474c7950a3fd0d5cf3b2d9e0\
01dac3aefc9d27da79439a4f6d3c501bbcf109075e6921e2c20e7327d151a47e\
a0e14f31383bf708687fcbe468d0820052a7eec56b3bb0000032b39b31b2cdc5\
1ecd96416fdda87af5eb913c4d1be205e05f948db1bb609965c1c1cb24b28a7a\
3d4865cbd91ff2765a09ef25687ecf5f02c04f3a47d1c8c71902ba93d28dbde1\
cae6b307abacea87ecd83b059d64eff2f4f49e649b92a1f7363e9de035e55a55\
3f51059dcef4190a2cccd4cf08548e20958cf02e4eb24adc564db8d8285eea06\
7f50322382de44ba0ac90fded5581921306c81b5127205ba74606d20f7fe4627\
83105fe6762d9d9ae63150d46c2c1744c267438a6b3cfa34f12908c66d977f4b\
c0"
            .to_string(),
        )
        .unwrap()[..];

        let got = sha256(&[i]);
        let want = &hex2bytes(
            "88b8e2c8cda021bc570f1ef7670fc1bcd01c69b9c9ca144bccae7367a981955c".to_string(),
        )
        .unwrap()[..];

        assert_eq!(got, want);
    }

    #[test]
    fn test_srp() {
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

        const KEY_SIZE: u32 = 2048;

        // C & S
        //     Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
        //
        // openssl dhparam -text 2048 # "2048 bit long safe prime"
        // openssl prime -generate -bits 1024 -safe -hex
        //
        // use openssl::bn::BigNum;
        // let mut bn = BigNum::new().unwrap();
        // assert!(bn.generate_prime(KEY_SIZE as i32, true, None, None).is_ok());
        // let n = BigUint::from_bytes_be(&bn.to_vec());
        //
        // Fixed to speed up tests
        let n = BigUint::parse_bytes(
            b"\
            00d5137edacb404e7a327a71a9e25fbbc9de87d24814b488d88eb57cfff9\
            00ae7de593647094fa4382179c9228d9e68504bcace9d2fd73814316b5a5\
            196b880fdde537f003362f5673e69cc9de6f74e1e4394728bfc2c9297e5c\
            d994dd418a7b2e99b5fff5da52c4572d65604b5c2f616dece63d5b389196\
            1787b445a4fdbab5ab4ba93f2fce5dcc036d75bf98e62774090779ac9989\
            fa469c9017fa64dafc864329a826fa967459ed35abaf07caab8600129766\
            7a29586e04871f4e4c1d7619fe3a77ff71865b79d4500eca7f2c8e7f8d1c\
            f71075b1c497dc35d0909f157372f645952cd95bcf2fcd852993491c9bca\
            43cdc1915021a7c2c4342a088d013541ef",
            16,
        )
        .unwrap();
        // println!("n={:02x?}", &n.to_bytes_be());
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
        let ka = g.clone().modpow(&a, &n);
        // println!("a={}", a);

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
        // Expert version inspired by
        // https://github.com/RustCrypto/PAKEs/blob/master/srp/src/client.rs
        // let sc_base = (&k * &g.modpow(&x, &n)) % &n;
        // let sc_base = ((&kb + &n) - &sc_base) % &n; // Adding N to B in case B < base.
        // let sc2 = sc_base.modpow(&(&a + &u * &x), &n);
        // println!("sc2={:02x?}", &sc2);
        let sc = (&kb - (&k * &g.modpow(&x, &n))).modpow(&(&a + &u * &x), &n);
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
