use std::collections::HashMap;

pub fn detec_ecb(input: &[u8], keylen: usize) -> bool {
    let mut blocks: HashMap<&[u8], i32> = HashMap::new();
    let mut identical = 0;

    for block in input.chunks(keylen) {
        if blocks.contains_key(block) {
            identical += 1;
        }
        else {
            blocks.insert(block, 1);
        }
    }

    return identical > 0;
}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufReader,BufRead};
    use openssl::symm::{decrypt, Cipher};

    use b64;
    use b64::{hex2bytes};
    use super::*;

    #[test]
    fn test_aes_decrypt() {
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
        assert!(detec_ecb(aes_128_ecb_encoded, 16));
    }

    #[test]
    fn test_detect_ecb_sample() {
        let file = File::open("data/8.txt").unwrap();
        let mut found: Vec<i32> = Vec::new();
        let mut line_idx = 0;
        for line in BufReader::new(file).lines() {
            line_idx += 1;
            let raw = hex2bytes(line.unwrap()).unwrap();
            let ding = detec_ecb(&raw, 16);
            if ding {
                found.push(line_idx);
            }
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], 133);
    }

}
