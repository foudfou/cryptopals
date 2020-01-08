#[cfg(test)]
mod tests {

    use chrono::Utc;
    use rug::{rand::RandState, Integer};
    use std::process;

    fn hex(s: &str) -> Integer {
        Integer::from_str_radix(s, 16).unwrap()
    }

    #[test]
    fn test_diffie_hellman() {
        let p = Integer::from(37);
        let g = Integer::from(5);

        let now = Utc::now().timestamp();
        let mut rand = RandState::new();
        rand.seed(&Integer::from(now / (process::id() as i64)));

        let rand_min = 16;
        let rand_max = 128;
        let mut a: Integer = Integer::from(rand_max + rand_min) + rand_min;
        a.random_below_mut(&mut rand);
        // A = (g**a) % p, Alice pub key
        let ka = g.clone().pow_mod(&a, &p).unwrap();
        // B = (g**b) % p, Bob pub key
        let mut b: Integer = Integer::from(rand_max + rand_min) + rand_min;
        b.random_below_mut(&mut rand);
        let kb = g.clone().pow_mod(&b, &p).unwrap();

        // K = B**a % p = A**b % p
        let sa = kb.clone().pow_mod(&a, &p).unwrap();
        let sb = ka.clone().pow_mod(&b, &p).unwrap();
        assert_eq!(sa, sb);

        // TODO let key = sha256(sa); // 128 bits would be md5()

        let g2 = Integer::from(2);
        let p2 = hex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                      e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                      3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                      6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                      24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                      c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                      bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                      fffffffffffff");
        let ka2 = g2.clone().pow_mod(&a, &p2).unwrap();
        let kb2 = g2.clone().pow_mod(&b, &p2).unwrap();
        let sa2 = kb2.clone().pow_mod(&a, &p2).unwrap();
        let sb2 = ka2.clone().pow_mod(&b, &p2).unwrap();
        // println!("a={} b={} sa2={}, sb2={}", a, b, sa2, sb2);
        assert_eq!(sa2, sb2);
    }
}
