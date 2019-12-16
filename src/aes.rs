use std::collections::HashMap;

///! This ECB detection works for sufficiently long texts where a whole block
///! is repeated.
pub fn detect_ecb(input: &[u8], blocksize: usize) -> bool {
    let mut blocks: HashMap<&[u8], i32> = HashMap::new();
    let mut identical = 0;

    for block in input.chunks(blocksize) {
        if blocks.contains_key(block) {
            identical += 1;
        } else {
            blocks.insert(block, 1);
        }
    }

    identical > 0
}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::io;

    use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};

    use b64::hex2bytes;
    use b64;
    use pkcs;
    use xor::xor;
    use super::*;

    #[test]
    fn test_aes_128_ecb_decrypt() {
        let mut cipher: Vec<u8> = Vec::new();
        b64::read_file("data/7.txt", &mut cipher);
        let key = b"YELLOW SUBMARINE";
        let enc = Cipher::aes_128_ecb();
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let plain = decrypt(enc, key, Some(iv), &cipher).unwrap();
        // let pl = String::from_utf8(plain).unwrap();
        let head = b"I'm back and I'm ringin' the bell";
        assert_eq!(&head[..], &plain[0..33]);
    }

    #[test]
    fn test_detect_ecb() {
        // let plain = "abcdefghijklmnopabcdefghijklmnop";
        // let key = b"YELLOW SUBMARINE";
        let aes_128_ecb_encoded =
            b"\xbd\xb1\x84\xd4\x4e\x1f\xc1\xd3\x06\x09\x45\xb5\x3c\x99\x4f\x48\
              \xbd\xb1\x84\xd4\x4e\x1f\xc1\xd3\x06\x09\x45\xb5\x3c\x99\x4f\x48\
              \x60\xfa\x36\x70\x7e\x45\xf4\x99\xdb\xa0\xf2\x5b\x92\x23\x01\xa5";
        assert!(detect_ecb(aes_128_ecb_encoded, 16));
    }

    #[test]
    fn test_detect_ecb_sample() {
        let file = File::open("data/8.txt").unwrap();
        let mut found: Vec<i32> = Vec::new();
        let mut line_idx = 0;
        for line in BufReader::new(file).lines() {
            line_idx += 1;
            let raw = hex2bytes(line.unwrap()).unwrap();
            let ding = detect_ecb(&raw, 16);
            if ding {
                found.push(line_idx);
            }
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], 133);
        // Never found the key nor the plaintext
    }

    ///! This CBC encryption is ONLY for learning purpose. It uses per-block
    ///! ECB encoding. Use the openssl primitives for realworld work.
    ///! https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
    fn aes_128_cbc_encrypt(
        input: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>, io::Error> {
        let padded = pkcs::pkcs7_pad(input, 16)?;

        let mut res: Vec<u8> = Vec::new();
        let mut prev = iv.to_vec();
        for block in padded.chunks(16) {
            let xored = &xor(&prev[..], block);

            // Using `encrypt()` doesn't work. So we lift an example from symm
            let mut c = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
            c.pad(false);
            prev = vec![0; 16 + Cipher::aes_128_ecb().block_size()];
            // FIXME: uh? no need to wrap openssl error into io::Error ?
            let count = c.update(xored, &mut prev)?;
            let rest = c.finalize(&mut prev[count..])?;
            prev.truncate(count + rest);
            res.extend(prev.iter().cloned());
        }
        Ok(res)
    }

    ///! Theis CBC decryption is ONLY for learning purpose. It uses per-block
    ///! ECB encoding. Use the openssl primitives for realworld work.
    ///! https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
    fn aes_128_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut res: Vec<u8> = Vec::new();
        let mut prev = iv;
        for block in input.chunks(16) {
            // Using `decrypt()` doesn't work. So we lift an example from symm
            let mut c = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
            c.pad(false);
            let mut out = vec![0; 16 + Cipher::aes_128_ecb().block_size()];
            let count = c.update(block, &mut out)?;
            let rest = c.finalize(&mut out[count..])?;
            out.truncate(count + rest);

            let xored = &xor(prev, &out);
            res.extend(xored.iter().cloned());
            prev = block;
        }

        pkcs::pkcs7_unpad(&res)
    }

    #[test]
    fn test_encrypt_cbc_sample() {
        let key = b"YELLOW SUBMARINE";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let plain = b"I'm back and I'm ringin' the bell";
        let cipher = aes_128_cbc_encrypt(plain, key, iv).unwrap();
        let want = b"\x09\x12\x30\xaa\xde\x3e\xb3\x30\xdb\xaa\x43\x58\xf8\x8d\x2a\x6c\
              \xd5\xcf\x83\x55\xcb\x68\x23\x39\x7a\xd4\x39\x06\xdf\x43\x44\x55\
              \xa6\x1f\x98\x55\xbe\x80\xc5\x03\xe5\x6e\xae\xae\x96\x2b\x3c\x98";
        assert_eq!(cipher, want.to_vec());
    }

    #[test]
    fn test_decrypt_cbc_sample() {
        let mut cipher: Vec<u8> = Vec::new();
        b64::read_file("data/10.txt", &mut cipher);
        let key = b"YELLOW SUBMARINE";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let plain = aes_128_cbc_decrypt(&cipher, key, iv).unwrap();
        let head = b"I'm back and I'm ringin' the bell";
        assert_eq!(&head[..], &plain[0..33]);
        // let pl = String::from_utf8(plain).unwrap();
        assert_eq!(plain.len(), 2876);
    }

    #[test]
    fn test_aes_128_cbc_encrypt() {
        let data = b"Some Crypto Text";
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
        let cipher = encrypt(Cipher::aes_128_cbc(), key, Some(iv), data).unwrap();
        let want = b"\xB4\xB9\xE7\x30\xD6\xD6\xF7\xDE\x77\x3F\x1C\xFF\xB3\x3E\x44\x5A\
                     \x91\xD7\x27\x62\x87\x4D\xFB\x3C\x5E\xC4\x59\x72\x4A\xF4\x7C\xA1";
        assert_eq!(&cipher[..], want);
    }

    use rand::prelude::*;

    #[derive(PartialEq)]
    enum AesMode {ECB, CBC,}

    ///! Encrypts randomly in AES ECB or CBC, with random key, random left and
    ///! right pads.
    fn aes_rand_encrypt(input: &[u8]) -> Result<(Vec<u8>, AesMode), openssl::error::ErrorStack> {
        let mut rng = rand::thread_rng();

        let mut lpad = [0u8; 10];
        let lpad_len = rng.gen_range(5, 11);
        rng.fill_bytes(&mut lpad[0..lpad_len]);

        let mut rpad = [0u8; 10];
        let rpad_len = rng.gen_range(5, 11);
        rng.fill_bytes(&mut rpad[0..rpad_len]);

        let padded = [&lpad[0..lpad_len], input, &rpad[0..rpad_len]].concat();

        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);

        let mut iv = [0u8; 16];
        let (mode, cipher, iv) = if rand::random() {
            (AesMode::ECB, Cipher::aes_128_ecb(), None)
        } else {
            rng.fill_bytes(&mut iv);
            (AesMode::CBC, Cipher::aes_128_cbc(), Some(&iv[..]))
        };
        let enc = encrypt(cipher, &key, iv, &padded)?;
        Ok((enc, mode))
    }

    #[test]
    fn test_aes_rand_detect() {
        // We can detect ECB if the input is large enough.
        let input = [b'A'; 48];
        for _ in 0..100 {
            let (aes_128_rand_encoded, aes_mode) = aes_rand_encrypt(&input).unwrap();
            let ecb_detected = detect_ecb(&aes_128_rand_encoded, 16);
            assert!(ecb_detected == (aes_mode == AesMode::ECB));
        }
    }

    trait Encrypter {
        fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack>;
    }

    struct UnknownEncrypter { key: [u8; 16], secret: Option<Vec<u8>>}

    impl UnknownEncrypter {

        fn new() -> UnknownEncrypter {
            let mut rng = rand::thread_rng();

            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);

            let secret= b64::decode(
                b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                  YnkK"
            ).unwrap();

            UnknownEncrypter { key: key, secret: Some(secret), }
        }

    }

    impl Encrypter for UnknownEncrypter {

        // AES-128-ECB(your-string || unknown-string, random-key)
        fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let sec = self.secret.as_ref().unwrap();
            let padded = [input, &sec].concat();
            encrypt(Cipher::aes_128_ecb(), &self.key, None, &padded)
        }

    }

    // We need 2 consecutive identical blocks.
    // FIXME better, use PKCS7 padding: if adding 1 byte adds more to the encoded
    fn guess_ecb_block_size(enc: &mut UnknownEncrypter) -> i32 {
        for bsize in 8..=256 {
            let input = vec![b'A'; 2*bsize];
            let encoded = enc.encrypt(&input).unwrap();
            if &encoded[0..bsize] == &encoded[bsize..2*bsize] {
                return bsize as i32
            }
        }
        -1
    }

    fn guess_ecb_secret_size(enc: &mut UnknownEncrypter, blk_size: usize) -> Option<usize> {
        let len = enc.encrypt(&[]).unwrap().len();
        println!("len={}", len);
        for i in 1..blk_size {
            let input = vec![b'A'; i];
            let len_cur = enc.encrypt(&input).unwrap().len();
            if len_cur != len {
                return Some(len - i)
            }
        }
        None
    }

    use std::convert::TryInto;

    #[test]
    fn test_ecb_oracle() {
        // FIXME why mut ?
        let mut unknown = UnknownEncrypter::new();
        let block_size_in_bytes = guess_ecb_block_size(&mut unknown);
        let bsize = block_size_in_bytes.try_into().unwrap();
        assert_eq!(bsize, 16);
        let encoded = unknown.encrypt(&mut vec![b'A'; 2*bsize]).unwrap();
        assert!(detect_ecb(&encoded, bsize));

        let secret_size = guess_ecb_secret_size(&mut unknown, bsize).unwrap();
        assert_eq!(secret_size, 138);

        let mut clear: Vec<u8> = Vec::new();
        'blocks: for j in 0..encoded.len()/bsize {
            for i in 1..=bsize {
                // println!("\n======> i={}, j={}", i, j);
                let pad = vec![b'A'; bsize-i];

                // FIXME actually can stop at first match
                let mut candidates = HashMap::new();
                for b in 0u8..=255 {
                    let mut input = pad.clone();
                    input.append(&mut clear.clone());
                    input.push(b);
                    // println!("{:?}", input);
                    let enc = unknown.encrypt(&input).unwrap();
                    let blk = enc[j*bsize..(j+1)*bsize].to_vec();
                    // println!("{:?} -> {}", &blk, b);
                    candidates.insert(blk, b);
                }

                let enc = unknown.encrypt(&pad).unwrap();
                clear.push(candidates[&enc[j*bsize..(j+1)*bsize]]);
                println!("{} == {}", clear.len(), secret_size);
                if clear.len() == secret_size { break 'blocks; }
            }
        }

        // println!("-> {:?}", clear.iter().map(|&c| c as char).collect::<String>());
        assert_eq!(clear, unknown.secret.unwrap());
    }

}
