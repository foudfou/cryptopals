use std::io;

pub fn fixed_xor(text: &[u8], key: &[u8]) -> Result<Vec<u8>, io::Error> {
    if text.len() != key.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
                                  "Text and key differ in length "));
    }

    let cipher: Vec<u8> = text.iter()
        .zip(key.iter())
        .map(|(&x, &y)| x ^ y)
        .collect();

    return Ok(cipher);
}



#[cfg(test)]
mod tests {
    use b64::hex2bytes;
    use super::*;

    #[test]
    fn test_fixed_xor() {
        let text1   = hex2bytes("1c0111001f010100061a024b53535009181c".to_string()).unwrap();
        let key1    = hex2bytes("686974207468652062756c6c277320657965".to_string()).unwrap();
        let cipher1 = hex2bytes("746865206b696420646f6e277420706c6179".to_string()).unwrap();
        assert_eq!(fixed_xor(&text1, &key1).unwrap(), cipher1);
    }

}
