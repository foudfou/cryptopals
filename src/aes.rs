
#[cfg(test)]
mod tests {
    use b64;

    use openssl::symm::{decrypt, Cipher};

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

}
