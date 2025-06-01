#[cfg(test)]
mod tests {

    use std::collections::HashMap;
    use std::str;

    use openssl::symm::{decrypt, encrypt, Cipher};
    use rand::prelude::*;

    use crate::pkcs;

    fn kv_parse(params: String) -> HashMap<String, String> {
        params
            .split('&')
            .map(|pair| pair.splitn(2, '=').collect())
            .map(|v: Vec<&str>| (v[0].to_string(), v[1].to_string()))
            .collect()
    }

    // Could also use hashmap macro https://stackoverflow.com/a/28392068/421846
    fn to_map(v: Vec<(&str, &str)>) -> HashMap<String, String> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn test_kv_parse() {
        let obj = kv_parse("foo=bax&baz=qux&zap=zazzle&foo=bar".to_string());
        let wanted: HashMap<String, String> =
            to_map(vec![("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")]);
        assert_eq!(obj, wanted);
    }

    fn profile_for_as_map(email: &str) -> HashMap<String, String> {
        to_map(vec![("email", email), ("uid", "10"), ("role", "user")])
    }

    fn profile_for_plain(email: &str) -> String {
        let escaped = email.replace('=', "%26").replace('&', "%3D");
        format!("email={}&uid=10&role=user", escaped)
    }

    pub struct ProfileEncrypter {
        key: [u8; 16],
    }

    impl ProfileEncrypter {
        fn new() -> ProfileEncrypter {
            let mut rng = rand::thread_rng();

            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);

            ProfileEncrypter { key: key }
        }

        fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            encrypt(Cipher::aes_128_ecb(), &self.key, None, &input)
        }

        fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            decrypt(Cipher::aes_128_ecb(), &self.key, None, &input)
        }
    }

    fn profile_for(
        email: &str,
        enc: &mut ProfileEncrypter,
    ) -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let plain = profile_for_plain(email);
        enc.encrypt(plain.as_bytes())
    }

    fn profile_from(
        input: &[u8],
        enc: &mut ProfileEncrypter,
    ) -> Result<HashMap<String, String>, String> {
        let clear = enc.decrypt(input).map_err(|e| e.to_string())?;
        let plain = String::from_utf8(clear).map_err(|e| e.to_string())?;
        Ok(kv_parse(plain))
    }

    #[test]
    fn test_profile_for_plain() {
        let foo_map = profile_for_as_map("foo@bar.com");
        let wanted: HashMap<String, String> = to_map(vec![
            ("email", "foo@bar.com"),
            ("uid", "10"),
            ("role", "user"),
        ]);
        assert_eq!(foo_map, wanted);

        assert_eq!(
            profile_for_plain("foo@bar.com"),
            "email=foo@bar.com&uid=10&role=user"
        );
        assert_eq!(
            profile_for_plain("foo@bar.com&role=admin"),
            "email=foo@bar.com%3Drole%26admin&uid=10&role=user"
        );
    }

    #[test]
    fn test_profile_oracle() {
        let mut unknown = ProfileEncrypter::new();

        // With multiple attempts, an attacker can first determine that the
        // encrypter is AES-ECB-128. Now, in reality, i doubt an attacker would
        // be able to guess the parameter keys, and especially that role is
        // at the end. Still, if we place wanted values at block boundaries, we
        // can cut-and-paste encrypted blocks to forge an admin profile:
        // [email=]foo@bar.co
        //  adminAAAAAAAAAAA
        //  AAA[&uid=10&role=
        //  user]PPPPPPPPPPPP
        let payload1 = "foo@bar.coadminAAAAAAAAAAAAAA";
        let enc1 = profile_for(payload1, &mut unknown).unwrap();
        let blks1: Vec<&[u8]> = enc1.chunks(16).collect();

        // But we also need a proper pkcs padding:
        // [email=]foo@bar.co
        //  admin...........
        // [&uid=10&role=use
        //  r]PPPPPPPPPPPPPPPP
        let admin16 = b"admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B";
        assert_eq!(admin16, &pkcs::pkcs7_pad(b"admin", 16).unwrap()[..]);
        let payload2 = ["foo@bar.co", str::from_utf8(admin16).unwrap()].concat();
        let enc2 = profile_for(&payload2, &mut unknown).unwrap();
        let blks2: Vec<&[u8]> = enc2.chunks(16).collect();

        // [email=]foo@bar.co
        //  AAA[&uid=10&role=
        //  admin...........
        let tampered = [blks1[0], blks1[2], blks2[1]].concat();
        let fake = profile_from(&tampered, &mut unknown).unwrap();
        let wanted: HashMap<String, String> = to_map(vec![
            ("email", "foo@bar.coAAA"),
            ("uid", "10"),
            ("role", "admin"),
        ]);
        assert_eq!(fake, wanted);
    }
}
