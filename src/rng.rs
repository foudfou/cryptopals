/// Directly copy-pasted from the original MT19937 C code by Takuji Nishimura
/// and Makoto Matsumoto.
/// http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908b0df;      /* constant vector a */
const MAG01: [u32; 2] = [0, MATRIX_A]; /* mag01[x] = x * MATRIX_A  for x=0,1 */
const UPPER_MASK: u32 = 0x80000000;    /* most significant w-r bits */
const LOWER_MASK: u32 = 0x7fffffff;    /* least significant r bits */

pub struct MT19937 {
    mt: [u32; N],               /* the array for the state vector  */
    mti: usize,                 /* mti==N+1 means mt[N] is not initialized */
}

impl MT19937 {

    pub fn new(seed: u32) -> MT19937 {
        let mut rng = MT19937 {
            mt: [0u32; N],
            mti: N+1,
        };

        rng.mt[0] = seed;
        for i in 1..N {
            rng.mt[i] = 1812433253u32 // aka 0x6c078965
                .wrapping_mul(rng.mt[i-1] ^ (rng.mt[i-1] >> 30))
                .wrapping_add(i as u32);
            /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
            /* In the previous versions, MSBs of the seed affect   */
            /* only MSBs of the array mt[].                        */
            /* 2002/01/09 modified by Makoto Matsumoto             */
        }
        // F**ing C post-increment! The orinal code is `for (mti=1; mti<N;
        // mti++)` ...which leaves mti at N!
        rng.mti = N;

        rng
    }

    /* generates a random number on [0,0xffffffff]-interval */
    pub fn rand_u32(&mut self) -> u32 {
        if self.mti >= N {       //* generate N words at one time */
            if self.mti == N+1 { //* if init_genrand() has not been called, */
                panic!("Generator was never seeded");
            }

            self.twist()
        }

        /* Tempering */
        let mut y = self.mt[self.mti];
        self.mti += 1;

        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680u32;
        y ^= (y << 15) & 0xefc60000u32;
        y ^= y >> 18;

        return y;
    }

    fn twist(&mut self) {
        for kk in 0..N-M {
            let y = (self.mt[kk]&UPPER_MASK)|(self.mt[kk+1]&LOWER_MASK);
            self.mt[kk] = self.mt[kk+M] ^ (y >> 1) ^ MAG01[y as usize & 0x1];
        }
        for kk in N-M..N-1 {
            let y = (self.mt[kk]&UPPER_MASK)|(self.mt[kk+1]&LOWER_MASK);
            self.mt[kk] = self.mt[kk+M-N] ^ (y >> 1) ^ MAG01[y as usize & 0x1];
        }
        let y = (self.mt[N-1]&UPPER_MASK)|(self.mt[0]&LOWER_MASK);
        self.mt[N-1] = self.mt[M-1] ^ (y >> 1) ^ MAG01[y as usize & 0x1];

        self.mti = 0;
    }

}

#[cfg(test)]
pub mod tests {
    use ::rng::MT19937;

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
        let before = NaiveDate::from_ymd(2019, 12, 30).and_hms(4, 43, 19).timestamp();
        let seed = u32::try_from(before).unwrap();
        let out = MT19937::new(seed).rand_u32();

        let now = NaiveDate::from_ymd(2019, 12, 30).and_hms(5, 23, 03).timestamp();

        let not_before = u32::try_from(
            NaiveDate::from_ymd(2019, 12, 30).and_hms(0, 0, 0).timestamp()
        ).unwrap();

        let mut s = u32::try_from(now).unwrap();
        loop {
            let mut rng = MT19937::new(s);
            let got = rng.rand_u32();
            if got == out {break}
            if s < not_before {panic!("Seed not found")}
            s -= 1;
        }
        assert_eq!(s, seed);
    }

}
