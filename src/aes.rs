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

    use openssl::symm::{decrypt, Cipher, Crypter, Mode};

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

}
