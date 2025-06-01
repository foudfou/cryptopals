#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::{thread, time};

    use rand::prelude::*;

    use crate::hmac::*;
    use crate::par::*;
    use crate::sha::sha1;

    fn rand_key(min: usize, max: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; max];
        rng.fill_bytes(&mut key);

        let key_len: usize = rng.gen_range(min..max + 1);
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
    fn test_hmac_sha1_timing_attack_artificial() {
        //! The goal is to forge a valid hmac for a given message. So we just
        //! brute-force one byte at a time, knowing the good ones are the ones
        //! that took longest.
        //!
        //! We don't follow the instructions and just call insecure_compare()
        //! instead of calling a managed http server.

        // Under 20ms we already observe that some failed byte comparisons
        // sometimes take more than expected, leading to false guesses.
        const DELAY_MILLIS: u64 = 50;

        let unknown_key = rand_key(6, 32);
        let msg = b"hi there";
        let unknown_hmac = hmac(&unknown_key, msg, sha1, 64);
        println!("{:x?}", unknown_hmac);

        let n_workers = 4;
        let pool = ThreadPool::new(n_workers);
        let (tx, rx) = mpsc::channel();

        struct ReqTime {
            hmac: Vec<u8>,
            ms: time::Duration,
        }

        fn time_req<F>(hmac: Vec<u8>, req: F, tx: mpsc::Sender<ReqTime>)
        where
            F: Fn(Vec<u8>) -> bool,
        {
            let now = time::Instant::now();
            req(hmac.clone());
            let ms = now.elapsed();
            tx.send(ReqTime { hmac: hmac, ms: ms }).unwrap();
        }

        let sha1_byte_len = 20;
        let mut guessed_hmac = vec![0u8; sha1_byte_len];
        for i in 0..sha1_byte_len {
            for byte in 0..=255 {
                guessed_hmac[i] = byte;

                let key = unknown_key.clone();
                let req = move |hmac: Vec<u8>| {
                    sha1_hmac_verify_insecure(
                        &key,
                        msg,
                        &hmac,
                        time::Duration::from_millis(DELAY_MILLIS),
                    )
                };

                let tx = tx.clone();
                let hmac = guessed_hmac.clone();
                pool.execute(|| {
                    time_req(hmac, req, tx);
                });
            }

            let guess = rx.iter().take(256).fold(
                ReqTime {
                    hmac: vec![],
                    ms: time::Duration::from_millis(0),
                },
                |acc, t| {
                    if t.ms > acc.ms {
                        // println!("{:x} {:?}", byte, ms);
                        ReqTime {
                            hmac: t.hmac,
                            ms: t.ms,
                        }
                    } else {
                        acc
                    }
                },
            );

            guessed_hmac = guess.hmac;
            println!("{:x?}", guessed_hmac);
        }

        assert_eq!(guessed_hmac, unknown_hmac);
    }
}
