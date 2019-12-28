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
    use xor;
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

    /// This CBC encryption is ONLY for learning purpose. It uses per-block
    /// ECB encoding. Use the openssl primitives for realworld work.
    /// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
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

    /// Theis CBC decryption is ONLY for learning purpose. It uses per-block
    /// ECB encoding. Use the openssl primitives for realworld work.
    /// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
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

    /// This CTR encryption is ONLY for learning purpose. It uses per-block
    /// ECB encoding. Use the openssl primitives for realworld work.
    /// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
    ///
    /// Make sure `nonce` is random for each call !
    ///
    /// CTR decrypt is the same operation as encrypt.
    ///
    /// Note CTR does not need padding because the actual encryption (xor)
    /// happens bitwise. So it only uses the needed bits from the keystream.
    ///
    /// As a first approach, we will use the parameters given in the
    /// instructions:
    ///
    ///   [key=YELLOW SUBMARINE]
    ///   nonce=0
    ///   format=64 bit unsigned little endian nonce,
    ///          64 bit little endian block count (byte count / 16)
    fn aes_128_ctr_encrypt(
        input: &[u8],
        key: &[u8; 16],
        nonce: &[u8; 8], // aka iv
    ) -> Result<Vec<u8>, io::Error> {
        let mut res: Vec<u8> = Vec::new();

        for (block, count) in input.chunks(16).zip(0u64..) {
            let stream_in = [nonce.clone(), count.to_le_bytes()].concat();
            // openssl::symm::Crypter.update() requires output.len() >= input.len() + block_size.
            let mut stream_out = vec![0u8; 16 + Cipher::aes_128_ecb().block_size()];

            // Using `encrypt()` doesn't work. So we lift an example from symm
            let mut c = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
            c.pad(false);
            let updated = c.update(&stream_in, &mut stream_out)?;
            let rest = c.finalize(&mut stream_out[updated..])?;
            stream_out.truncate(updated + rest);

            let xored = &xor(block, &stream_out[..]);

            res.extend(xored);
        }
        Ok(res)
    }

    #[test]
    fn test_aes_128_ctr_encrypt() {
        let key = b"YELLOW SUBMARINE";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        let cypher = b64::decode(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").unwrap();
        let plain = aes_128_ctr_encrypt(&cypher, key, iv).unwrap();
        let want = [
            89, 111, 44, 32, 86, 73, 80, 32, 76, 101, 116, 39, 115, 32, 107, 105,
            99, 107, 32, 105, 116, 32, 73, 99, 101, 44, 32, 73, 99, 101, 44, 32,
            98, 97, 98, 121, 32, 73, 99, 101, 44, 32, 73, 99, 101, 44, 32, 98,
            97, 98, 121, 32
        ];
        assert_eq!(plain, want.to_vec());
    }

    fn make_cipher_from(strs: Vec<String>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>)
    {
        use rand::prelude::*;

        let mut rng = rand::thread_rng();
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);

        // For debugging purpose.
        let plains: Vec<Vec<u8>> = strs.iter().map(|txt| {
            let plain = b64::decode((*txt).as_bytes()).unwrap();
            // let clear = String::from_utf8_lossy(&plain);
            // println!("{} {:?}", clear.len(), clear);
            plain
        }).collect();

        let ciphers: Vec<Vec<u8>> = plains.iter().map(|plain| {
             // Should be randized for each encryption !
            let fixed_nonce = [0u8; 8];
            aes_128_ctr_encrypt(&plain, &key, &fixed_nonce).unwrap()
        }).collect();

        (ciphers, plains)
    }

    fn chall19_ciphers() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        make_cipher_from(vec![
            "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
            "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
            "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
            "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
            "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
            "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
            "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
            "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
            "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
            "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
            "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
            "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
            "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
            "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
            "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
            "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
            "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
            "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
            "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
            "U2hlIHJvZGUgdG8gaGFycmllcnM/",
            "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
            "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
            "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
            "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
            "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
            "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
            "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
            "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
            "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
            "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
            "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
            "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
            "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
            "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
            "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
            "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        ].into_iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn test_fixed_nonce_ctr() {
        let (ciphers, plains) = chall19_ciphers();

        // As nonce not randomized, All plain texts encrypted with same
        // keystream ! One possible attack would be to use the same encrypter
        // to deduce the keystream: C ^ P = Keystream, C and P being known.

        // Another way is to concatenate the first blocks of all ciphers, and
        // guess_xor on that, since we now have a fixed-length key.
        let block0: Vec<&[u8]> = ciphers.iter().map(|cipher| &cipher[..16]).collect();
        let keystream0 = xor::guess_xor(&block0.concat())
            .into_iter().find(|key| key.len() == 16).unwrap();
        // Not considering first byte as guess_xor() usually not reliable for a byte.
        assert_eq!(&xor(&plains[0], &keystream0)[1..16], &ciphers[0][1..16]);

        let block1: Vec<&[u8]> = ciphers.iter()
            .filter(|cipher| cipher.len() >= 32)
            .map(|cipher| &cipher[16..32])
            .collect();
        let keystream1 = xor::guess_xor(&block1.concat())
            .into_iter().find(|key| key.len() == 16).unwrap();
        let cipher1: &[u8] = &xor(&plains[4][16..32], &keystream1);
        let cipher1_want = &ciphers[4][16..32];
        let key_score1 = cipher1.iter()
            .zip(cipher1_want)
            .fold(0., |acc, (b1, b2)| if b1 == b2 {acc + 1.} else {acc})
            / 16.;
        assert!(key_score1 >= 0.8); // ...yeah too few (6) examples
    }

    #[test]
    // Another approach is to:
    // - consider all bytes at a given position in all ciphers
    // - brute-force the keystream byte so the plain bytes look like
    //   english
    //
    // A very cool solution is to manually guess via some UI:
    // https://fattybeagle.com/2017/01/03/cryptopals-challenge-19/
    fn test_fixed_nonce_ctr_2() {
        let (ciphers, plains) = chall19_ciphers();

        let mut keystream: Vec<u8> = Vec::new();

        for i in 0..40 {
            let cipher_bytes: Vec<u8> = ciphers.iter()
                .filter(|cipher| cipher.len() > i)
                .map(|cipher| cipher[i])
                .collect();

            let (max_score, key, _clear) =
                xor::guess_single_xor_en(&cipher_bytes);
            // println!("{}: {} {} {}", i, max_score, key, String::from_utf8_lossy(&_clear));

            if max_score > 100. {keystream.push(key)} else {break}
        }

        for (i, cipher) in ciphers.iter().enumerate() {
            let clear = xor::xor_strict(&cipher, &keystream);
            let clear_lower = String::from_utf8_lossy(&clear).to_lowercase();
            let plain_lower = String::from_utf8_lossy(&plains[i]).to_lowercase();
            // println!("{}|\n{}|", clear_str, plain_str);
            assert!(plain_lower.starts_with(&clear_lower));
        }
    }

    fn chall20_ciphers() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let file = File::open("data/20.txt").expect("no such file");
        let lines: Vec<String> = BufReader::new(file)
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect();
        make_cipher_from(lines)
    }

    #[test]
    // In this approach (chall20), we build a repeated-key XOR input by
    // truncating our collection of ciphertexts them to a common length (the
    // smallest ciphertext). Indeed the keystream will be the same in all
    // ciphers.
    fn test_fixed_nonce_ctr_3() {
        let (ciphers, plains) = chall20_ciphers();
        let smallest = ciphers.iter()
            .fold(std::usize::MAX, |acc, c| if c.len() < acc {c.len()} else {acc});

        let ciphertext = ciphers.iter()
            .map(|c| &c[..smallest])
            .collect::<Vec::<&[u8]>>()
            .concat();

        // use std::io::Write;
        // let mut out = std::io::stdout();
        // out.write_all(&ciphertext).unwrap();
        // out.flush().unwrap();

        let keys = xor::guess_xor(&ciphertext);
        let key = keys.first().unwrap();

        let clears = xor(&ciphertext, &key);

        for (clear, plain) in clears.chunks(smallest).zip(plains) {
            // println!("{}", String::from_utf8_lossy(&clear));
            assert!(plain.starts_with(clear));
        }
    }

}
