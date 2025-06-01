/// Directly copy-pasted from the original MT19937 C code by Takuji Nishimura
/// and Makoto Matsumoto.
/// http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908b0df; /* constant vector a */
const MAG01: [u32; 2] = [0, MATRIX_A]; /* mag01[x] = x * MATRIX_A  for x=0,1 */
const UPPER_MASK: u32 = 0x80000000; /* most significant w-r bits */
const LOWER_MASK: u32 = 0x7fffffff; /* least significant r bits */

pub struct MT19937 {
    mt: [u32; N], /* the array for the state vector  */
    mti: usize,   /* mti==N+1 means mt[N] is not initialized */
}

impl MT19937 {
    pub fn new(seed: u32) -> MT19937 {
        let mut rng = MT19937 {
            mt: [0u32; N],
            mti: N + 1,
        };

        rng.mt[0] = seed;
        for i in 1..N {
            rng.mt[i] = 1812433253u32 // aka 0x6c078965
                .wrapping_mul(rng.mt[i - 1] ^ (rng.mt[i - 1] >> 30))
                .wrapping_add(i as u32);
            /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
            /* In the previous versions, MSBs of the seed affect   */
            /* only MSBs of the array mt[].                        */
            /* 2002/01/09 modified by Makoto Matsumoto             */
        }
        // F**ing C post-increment! The orinal code is `for (mti=1; mti<N; mti++)`
        // ...which leaves mti at N!
        rng.mti = N;

        rng
    }

    /* generates a random number on [0,0xffffffff]-interval */
    pub fn rand_u32(&mut self) -> u32 {
        if self.mti >= N {
            //* generate N words at one time */
            if self.mti == N + 1 {
                //* if init_genrand() has not been called, */
                panic!("Generator was never seeded");
            }

            self.twist()
        }

        /* Tempering */
        let y = self.mt[self.mti];
        self.mti += 1;
        temper(y)
    }

    fn twist(&mut self) {
        for kk in 0..N - M {
            let y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK);
            self.mt[kk] = self.mt[kk + M] ^ (y >> 1) ^ MAG01[y as usize & 0x1];
        }
        for kk in N - M..N - 1 {
            let y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK);
            self.mt[kk] = self.mt[kk + M - N] ^ (y >> 1) ^ MAG01[y as usize & 0x1];
        }
        let y = (self.mt[N - 1] & UPPER_MASK) | (self.mt[0] & LOWER_MASK);
        self.mt[N - 1] = self.mt[M - 1] ^ (y >> 1) ^ MAG01[y as usize & 0x1];

        self.mti = 0;
    }
}

fn temper(i: u32) -> u32 {
    let mut y = i;
    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c5680u32;
    y ^= (y << 15) & 0xefc60000u32;
    y ^= y >> 18;
    y
}

#[cfg(test)]
pub mod tests {
    use crate::rng::MT19937;

    #[test]
    fn test_mt19937() {
        // Test vector from https://gist.githubusercontent.com/mimoo/8e5d80a2e236b8b6f5ed/raw/20a704e0ccb3d50ea574cf6fe81fcb07cd9a66a3/gistfile1.txt
        let seed1 = 1131464071;
        let mut rng1 = MT19937::new(seed1);
        let samples1: Vec<u32> = (0..700).into_iter().map(|_| rng1.rand_u32()).collect();
        assert_eq!(samples1[0], 3521569528);
        assert_eq!(samples1[699], 460066336);

        // Boost cpp
        let seed2 = 5489u32; /* Default initial seed in reference implementation */
        let mut rng2 = MT19937::new(seed2);
        let samples2: Vec<u32> = (0..10000).into_iter().map(|_| rng2.rand_u32()).collect();
        assert_eq!(samples2[9999], 4123659995);
    }

    use chrono::NaiveDate;
    use std::convert::TryFrom;

    fn new_timestamp(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
        NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(hour, min, sec)
            .unwrap()
            .and_utc()
            .timestamp()
    }

    #[test]
    fn test_crack_mt19937_seed() {
        //! Instructions are not clear. The function that generates a random
        //! number seeded with a unix timestamp only outputs one number. So we
        //! can just brute-force the seed. Covering ..std::u32::MAX requires 2h
        //! without parallelization. I'm not sure why the function should wait
        //! again before outputting the number. Anyways we can then restrict
        //! the exploration space to unix timestamps between now and -2*1000s.
        // let start = std::time::Instant::now();
        // if start.elapsed() > Duration::from_secs(3) {break}

        // Here we just simulate the passage of time
        let before = new_timestamp(2019, 12, 30, 4, 43, 19);
        let seed = u32::try_from(before).unwrap();
        let out = MT19937::new(seed).rand_u32();

        let now = new_timestamp(2019, 12, 30, 5, 23, 03);

        let not_before = u32::try_from(new_timestamp(2019, 12, 30, 0, 0, 0)).unwrap();

        let mut s = u32::try_from(now).unwrap();
        loop {
            let mut rng = MT19937::new(s);
            let got = rng.rand_u32();
            if got == out {
                break;
            }
            if s < not_before {
                panic!("Seed not found")
            }
            s -= 1;
        }
        assert_eq!(s, seed);
    }

    fn get_bits(u: u32, beg: usize, len: usize) -> u32 {
        if len == 0 {
            panic!("len == 0")
        }
        if beg > 32 {
            panic!("beg > 32")
        }
        if beg + len > 32 {
            panic!("beg + len > 32")
        }

        let mask: u32 = 0xffffffff;
        ((mask << beg) >> (32 - len)) & (u >> (32 - beg - len))
    }

    #[test]
    fn test_get_bits() {
        assert_eq!(get_bits(3009615726, 10, 10), 0x231);
        assert_eq!(get_bits(3009615726, 0, 10), 0x2cd);
        assert_eq!(get_bits(3009615726, 10, 20), 0x8c5db);
        assert_eq!(get_bits(3009615726, 0, 1), 1);
    }

    #[test]
    #[should_panic]
    fn test_get_bits_len_zero() {
        get_bits(3009615726, 0, 0);
    }

    #[test]
    #[should_panic]
    fn test_get_bits_too_much() {
        get_bits(3009615726, 32, 10);
    }

    /**
    http://krypt05.blogspot.com/2015/10/reversing-shift-xor-operation.html
    Note >> on unsigned ints fills with 0.

    (1) y        a(10)  | b(10)   | c(10)   | d(2)
    (2) y>>10    0(10)  | a(10)   | b(10)   | c(2)
    (3) y^y>>10  a(10)  | a^b(10) | b^c(10) | c^d(2)

    So to find (1) from (3), we need to xor a(10) with a^b(10) to get b(10),
    then b(10) with b^c(10) to get c(10), and finally c(2) with c^d(2) to get
    d(2).

    Note we can apply the same reasoning for a left shift:
    (1) y        a(2)   | b(10)   | c(10)   | d(10)
    (2) y<<10    b(2)   | c(10)   | d(10)   | 0(10)
    (3) y^y<<10  a^b(2) | b^c(10) | c^d(10) | d(10)
     */
    fn reverse_rshift_xor(u: u32, shift: usize) -> u32 {
        let mut a = get_bits(u, 0, shift);
        let mut res: u32 = a << (32 - shift);
        for i in 1..=32 / shift {
            let beg = i * shift;
            let len = if beg + shift <= 32 {
                shift
            } else {
                a >>= shift - 32 % shift;
                32 - beg
            };
            let b = get_bits(u, beg, len);
            a ^= b;
            res |= a << (32 - beg - len);
        }

        res
    }

    #[test]
    fn test_reverse_rshift_xor() {
        assert_eq!(reverse_rshift_xor(3009615726, 10), 3008349343);
        assert_eq!(reverse_rshift_xor(3076412325, 18), 3076423282);
        assert_eq!(reverse_rshift_xor(3008339256, 17), 3008349343);
        assert_eq!(reverse_rshift_xor(3598349337, 29), 3598349343);
    }

    /**
    For y ^= (y << 7) & 0x9d2c5680u32;

    (1) y        a(2)       | b(10)       | c(10)       | d(10)
    (2) y<<10    b(2)       | c(10)       | d(10)       | 0(10)
    (3) y^&      a^(b&m)(2) | b^(c&n)(10) | c^(d&o)(10) | d^(0&p)(10)

    So d(10) is given. Knowing d and o, we can get c. With c and knowing d and
    o, we can get b. And so on to the left.

    TODO test boundaries (shift>16 for ex.)
     */
    fn reverse_lshift_and_xor(u: u32, shift: usize, m: u32) -> u32 {
        let mut d = get_bits(u, 32 - shift, shift);
        let mut res: u32 = d;
        for i in 1..=32 / shift {
            let end = 32 - i * shift;
            let len = if end > shift {
                shift
            } else {
                d = get_bits(d, 32 - end, end);
                end
            };
            let k = get_bits(u, end - len, len);
            let o = get_bits(m, end - len, len);
            d = k ^ (d & o);
            res |= d << 32 - end;
        }
        res
    }

    #[test]
    fn test_reverse_lshift_and_xor() {
        assert_eq!(reverse_lshift_and_xor(577438062, 7, 0x9d2c5680), 3009615726);
        assert_eq!(
            reverse_lshift_and_xor(1064241006, 10, 0x9d2c5680),
            3009615726
        );
        assert_eq!(
            reverse_lshift_and_xor(954537838, 15, 0xefc60000),
            3009615726
        );
    }

    fn untemper(u: u32) -> u32 {
        let y1 = reverse_rshift_xor(u, 18);
        let y2 = reverse_lshift_and_xor(y1, 15, 0xefc60000);
        let y3 = reverse_lshift_and_xor(y2, 7, 0x9d2c5680);
        reverse_rshift_xor(y3, 11)
    }

    #[test]
    fn test_untemper() {
        assert_eq!(untemper(457947961), 3499211612);
        assert_eq!(crate::rng::temper(untemper(3499211612)), 3499211612);
        assert_eq!(untemper(4117162263), 457947961);
    }

    #[test]
    fn test_clone_mt19937() {
        let mut rng1 = MT19937::new(5489u32);
        let mut samples1: Vec<u32> = Vec::new();
        let mut state1: Vec<u32> = Vec::new();
        for _ in 0..624 {
            let r = rng1.rand_u32();
            samples1.push(r);
            state1.push(untemper(r));
        }

        let mut mt2 = [0u32; crate::rng::N];
        mt2.copy_from_slice(&state1[..624]);
        let mut rng2 = MT19937 { mt: mt2, mti: 0 };
        for i in 0..624 {
            let rand2 = rng2.rand_u32();
            assert_eq!(samples1[i], rand2);
        }

        /* « Stop and think for a second.  How would you modify MT19937 to make
        this attack hard? What would happen if you subjected each tempered
        output to a cryptographic hash? » Well, we would make the untemper
        function irreversible. By using destructive operations like & or |. Not
        sure how returning a hash of the tempered value as the result would
        help: we could use a rainbow table for all u32 values, which would just
        add one operation to the untempering. I wonder if the twist function
        can be reversed. */
    }

    use crate::xor::xor;

    struct StreamCipher {
        // For testing purpose.
        key: u32,
    }

    impl StreamCipher {
        fn new(key: u16) -> StreamCipher {
            StreamCipher { key: key as u32 }
        }

        fn encrypt(&mut self, input: &[u8]) -> Vec<u8> {
            let mut rng = MT19937::new(self.key);
            let mut res: Vec<u8> = Vec::new();

            for chunk in input.chunks(4) {
                let keystream = rng.rand_u32().to_be_bytes();
                let xored = &xor(chunk, &keystream);
                res.extend(xored);
            }

            res
        }
    }

    #[test]
    fn test_stream_cipher() {
        let key = 0x4142;
        let mut cipher = StreamCipher::new(key);
        let plain = b"FOUDIL WAS HERE 2019-01-04";
        let crypted = cipher.encrypt(plain);
        assert_eq!(cipher.encrypt(&crypted), plain);
    }

    /** Stream cipher key brute-force */
    fn stream_cipher_bf(ciphertext: Vec<u8>) -> Option<u16> {
        use std::collections::HashMap;

        let mut chunk_set = HashMap::new();
        for (i, chunk) in ciphertext.chunks(4).enumerate() {
            chunk_set.insert(chunk, i);
        }

        for k in 0x0u16..=0xffff {
            let mut cipher = StreamCipher::new(k);
            let enc = cipher.encrypt(&[b'A'; 64]);

            for chunk in enc.chunks(4) {
                let maybe_pos = chunk_set.get(chunk);
                if maybe_pos.is_some() {
                    let pos = maybe_pos.unwrap();
                    // we consider 2 successive blocks sufficient
                    if &ciphertext[(pos + 1) * 4] == &enc[(pos + 1) * 4] {
                        return Some(k);
                    }
                }
            }
        }

        None
    }

    use rand::prelude::*;

    #[test]
    fn test_crack_stream_cipher() {
        let mut rng = rand::thread_rng();

        let mut pre = [0u8; 32];
        let pre_len = rng.gen_range(1..33);
        rng.fill_bytes(&mut pre[..pre_len]);
        let known_plain = [b'A'; 14];
        let plain = [&pre[..pre_len], &known_plain[..]].concat();

        // Restricting space for test speed.
        let key: u16 = rng.gen_range(0x0..0xff); // rng.gen()
        let mut cipher = StreamCipher::new(key);

        let ciphertext = cipher.encrypt(&plain);

        /*
        By xor'ing the ciphertext with A's, we should be able to find *some*
        mt19937 generated values. How about we brute-force by generating all
        possible mt19937's with a seed of 16 bits, and try to find matching
        values ? Generating all 16bits keys and encrypting a plain requires
        <10s on my laptop.
         */
        // let start = Instant::now();
        let maybe_key = stream_cipher_bf(ciphertext);
        // println!("elapsed {}s", start.elapsed().as_secs());

        assert_eq!(maybe_key.unwrap(), key);
    }

    /* Instructions say; « Use the same idea to generate a random "password
    reset token" using MT19937 seeded from the current time. »

    My first interpretation was: « As we used mt19937 to do crypto stuff like
    stream cipher, also use it for crypto stuff like generating some random
    value. So go ahead and find the seed from some broken single random
    value. » But most solutions I saw were generating bytes from successive
    calls to mt19937. Who would use an uint32 or even an uint64 as a token
    anyway.

    Another interpretation I saw is: generate a token from real random bytes
    appended with a signature; then encrypt it with the previous mt19937-based
    stream cipher; finally break that.

    I think the best interpretation is to generate a realistic token which
    would require more that 4 bytes (32 bits) so from successive mt19937
    calls. */

    use chrono::{Duration, Utc};

    // fn time_secs_since_epoch_u32() -> u64 {
    //     use std::time::{SystemTime, UNIX_EPOCH};
    //     SystemTime::now()
    //         .duration_since(UNIX_EPOCH)
    //         .expect("Time went backwards")
    //         .as_secs()
    // }

    fn gen_password_reset_token(mut rng: MT19937) -> Vec<u8> {
        const TOKEN_LEN: usize = 8;
        let mut res: Vec<u8> = Vec::new();
        for _ in 0..TOKEN_LEN {
            res.push(rng.rand_u32().to_be_bytes()[3]);
        }
        res
    }

    fn crack_password_reset_token(token: Vec<u8>, delay_max: i64) -> Option<u32> {
        let mut time = Utc::now();
        let not_before = Utc::now() - Duration::seconds(delay_max);
        loop {
            let s = u32::try_from(time.timestamp()).unwrap();
            let r = MT19937::new(s);

            // Supposing we know the token gen algo.
            let tok = gen_password_reset_token(r);
            if tok == token {
                return Some(s);
            }
            if time < not_before {
                return None;
            }

            time = time - Duration::seconds(1);
        }
    }

    #[test]
    fn test_crack_password_reset_token() {
        const DELAY_MAX_SECS: i64 = 300;
        let mut rng = rand::thread_rng();
        let delay_secs = rng.gen_range(1..DELAY_MAX_SECS);
        let now = Utc::now() - Duration::seconds(delay_secs);
        let now_u32 = u32::try_from(now.timestamp()).unwrap();
        let rng = MT19937::new(now_u32);
        let token = gen_password_reset_token(rng);
        assert_eq!(
            crack_password_reset_token(token, DELAY_MAX_SECS).unwrap(),
            now_u32
        );
    }
}
