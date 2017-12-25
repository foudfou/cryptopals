use std::io;

fn letter_freq_en(ch: char) -> f32 {
    match ch {
        ' ' => 14.0,
        'a' | 'A' => 8.167,
        'b' | 'B' => 1.492,
        'c' | 'C' => 2.782,
        'd' | 'D' => 4.253,
        'e' | 'E' => 12.702,
        'f' | 'F' => 2.228,
        'g' | 'G' => 2.015,
        'h' | 'H' => 6.094,
        'i' | 'I' => 6.966,
        'j' | 'J' => 0.153,
        'k' | 'K' => 0.772,
        'l' | 'L' => 4.025,
        'm' | 'M' => 2.406,
        'n' | 'N' => 6.749,
        'o' | 'O' => 7.507,
        'p' | 'P' => 1.929,
        'q' | 'Q' => 0.095,
        'r' | 'R' => 5.987,
        's' | 'S' => 6.327,
        't' | 'T' => 9.056,
        'u' | 'U' => 2.758,
        'v' | 'V' => 0.978,
        'w' | 'W' => 2.360,
        'x' | 'X' => 0.150,
        'y' | 'Y' => 1.974,
        'z' | 'Z' => 0.074,
        _ => -10.0
    }
}

pub fn fixed_xor(text: &[u8], key: &[u8]) -> Result<Vec<u8>, io::Error> {
    if text.len() != key.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
                                  "Text and key differ in length "));
    }
    return Ok(xor(text, key));
}

pub fn xor(text: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher: Vec<u8> = text.iter()
        .zip(key.iter().cycle())
        .map(|(&x, &y)| x ^ y)
        .collect();
    return cipher;
}

pub fn guess_single_xor_en(cipher: &[u8]) -> (f32, u8, Vec<u8>) {
    let mut plain: Vec<u8> = vec![];
    let mut key: u8 = 0;
    let mut max = -10.0;
    for i in 0..256 {
        let k = i as u8;        // inclusive range not stable :(
        let text = xor(cipher, &[k]);
        let score = text.iter()
            .fold(0.0, |acc, &ch| acc + letter_freq_en(ch as char));
        if score > max {
            plain = text;
            key = k;
            max = score;
        }
    }
    (max, key, plain)
}



#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufReader,BufRead};

    use b64::hex2bytes;
    use super::*;

    #[test]
    fn test_fixed_xor() {
        let text1   = hex2bytes("1c0111001f010100061a024b53535009181c".to_string()).unwrap();
        let key1    = hex2bytes("686974207468652062756c6c277320657965".to_string()).unwrap();
        let cipher1 = hex2bytes("746865206b696420646f6e277420706c6179".to_string()).unwrap();
        assert_eq!(fixed_xor(&text1, &key1).unwrap(), cipher1);
    }

    #[test]
    fn test_xor() {
        let text1   = hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string()).unwrap();
        let key1    = b"X";
        let cipher1 = b"Cooking MC's like a pound of bacon";
        assert_eq!(xor(&text1, key1), cipher1.to_vec());
    }

    #[test]
    fn test_guess_single_byte_xor() {
        let cipher = hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string()).unwrap();
        let text = b"Cooking MC's like a pound of bacon";
        let (_, key, plain) = guess_single_xor_en(&cipher);
        assert_eq!(key, 'X' as u8);
        assert_eq!(text.to_vec(), plain.to_vec());
    }

    #[test]
    fn test_detect_single_byte_xor() {
        let mut key: u8 = 0;
        let mut max = -10.0;
        let file = File::open("data/4.txt").unwrap();
        for line in BufReader::new(file).lines() {
            let raw = hex2bytes(line.unwrap()).unwrap();
            let (score, k, _) = guess_single_xor_en(&raw);
            // let plain_res =  str::from_utf8(&plain);
            if score > max {
                max = score;
                key = k;
            }
        }
        assert_eq!(key, '5' as u8);
    }

}
