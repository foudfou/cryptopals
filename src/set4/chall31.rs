#[cfg(test)]
mod tests {
    use std::{thread, time};

    use rand::prelude::*;

    use hmac::*;
    use sha::sha1;

    fn rand_key(min: usize, max: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; max];
        rng.fill_bytes(&mut key);

        let key_len: usize = rng.gen_range(min, max + 1);
        (&key[..key_len]).to_vec()
    }

    /// Aka insecure_compare()
    ///
    /// https://stackoverflow.com/a/44700409/421846 explains that Constant Time
    /// code is really hard. One reason is that we don't necessarily control
    /// the compiler's output. If we really want CT then we must use
    /// assembly.
    pub fn sha1_hmac_verify_insecure(
        key: &[u8],
        msg: &[u8],
        mac: &[u8],
        delay: time::Duration,
    ) -> bool {
        let hmac = hmac(key, msg, sha1, 64);

        for (i, b) in hmac.into_iter().enumerate() {
            if mac[i] != b {
                return false;
            }
            thread::sleep(delay);
        }
        return true;
    }

    #[test]
    #[ignore]
    fn test_hmac_sha1_timing_attack_easy() {
        //! The goal is to forge a valid hmac for a given message. So we just
        //! brute-force one byte at a time, knowing the good ones are the ones
        //! that took longest.
        //!
        //! We don't follow the instructions and just call insecure_compare()
        //! instead of calling a managed http server.

        // With 5ms we already observe that some false byte comparison can
        // sometimes take more than expected, leading to false guesses.
        const DELAY_MILLIS: u64 = 20;

        let unknown_key = rand_key(6, 32);
        let msg = b"hi there";

        let sha1_byte_len = 20;
        let mut guessed_hmac = vec![0u8; sha1_byte_len];
        for i in 0..sha1_byte_len {
            // TODO parallelize
            let mut duration_max = time::Duration::from_millis(0);
            let mut guessed_byte = 0u8;
            for byte in 0..=255 {
                guessed_hmac[i] = byte;
                let now = time::Instant::now();
                sha1_hmac_verify_insecure(
                    &unknown_key,
                    msg,
                    &guessed_hmac,
                    time::Duration::from_millis(DELAY_MILLIS),
                );
                let ms = now.elapsed();
                if ms > duration_max {
                    // println!("{:x} {:?}", byte, ms);
                    guessed_byte = byte;
                    duration_max = ms;
                }
            }
            guessed_hmac[i] = guessed_byte;
            println!("{:x?}", guessed_hmac);
        }

        let unknown_hmac = hmac(&unknown_key, msg, sha1, 64);
        assert_eq!(guessed_hmac, unknown_hmac);
    }
}
