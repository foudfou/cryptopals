use std::collections::BTreeMap;
use std::cmp;
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
        '!'...'/' | ':'...'@' | '\n' => 0.0,
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

fn popcount_aux(ch: u64, acc: u8) -> u8 {
    if ch == 0 {
        acc
    } else {
        popcount_aux(ch >> 1, acc + (ch & 1) as u8)
    }
}

fn popcount(ch: u64) -> u8 {
    popcount_aux(ch, 0)
}

/// Aka *edit distance*, is the number of differing bits
pub fn hamming_distance(src: &[u8], dst: &[u8]) -> Result<u32, io::Error> {
    if src.len() != dst.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Strings differ in length "));
    }

    return Ok(
        src.iter()
            .zip(dst.iter())
            .fold(0, |acc, (&x, &y)| acc + popcount(x as u64 ^ y as u64) as u32)
    );
}

pub fn guess_xor_keylen(cipher: &[u8], take: usize) -> Vec<usize> {
    let mut keysizes_by_dist: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    // Since we're applying a hamming distance, we need at least 2 chunks.
    for keysize in 2..(cmp::min(40, cipher.len() / 2) + 1) {
        let chunks: Vec<&[u8]> = cipher.chunks(keysize).collect();
        let mut dist_count = 0;
        let dist_sum = chunks[1..].iter().fold(0, |acc, ch| {
            match hamming_distance(chunks[0], ch) {
                Ok(d) => {dist_count += 1; acc + d},
                Err(_) => acc
            }
        });
        let dist_norm = dist_sum / dist_count / keysize as u32;
        let ksizes = keysizes_by_dist.entry(dist_norm).or_insert(Vec::new());
        ksizes.push(keysize);
    }

    keysizes_by_dist.iter()
        .flat_map(|(_dist, ksizes)| ksizes)
        .map(|&size| size)
        .take(take)
        .collect()
}

pub fn guess_xor(cipher: &[u8]) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = vec![];

    for keylen in guess_xor_keylen(cipher, 3) {
        let mut transposed = Vec::new();
        for _ in 0..keylen {
            transposed.push(Vec::new());
        }

        for (i, &ch) in cipher.iter().enumerate() {
            transposed[i % keylen].push(ch);
        }

        keys.push(transposed.iter().map(|v| guess_single_xor_en(&v).1).collect());
    }

    keys
}



#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufReader,BufRead};

    use b64;
    use b64::{hex2bytes};
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

    #[test]
    fn test_xor2() {
        let cipher = hex2bytes("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".to_string()).unwrap();
        let key    = b"ICE";
        let plain  = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        assert_eq!(xor(&cipher, key), plain.to_vec());
    }

    #[test]
    fn test_popcount() {
        assert_eq!(popcount(0), 0);
        assert_eq!(popcount(1), 1);
        assert_eq!(popcount(3), 2);
        assert_eq!(popcount(8), 1);
        assert_eq!(popcount(12), 2);
    }

    #[test]
    fn test_hamming_distance() {
        let src = b"this is a test";
        let dst = b"wokka wokka!!!";
        assert_eq!(hamming_distance(src, dst).unwrap(), 37);
    }

    #[test]
    fn test_guess_xor_keylen() {
        let cipher = hex2bytes("15041215511504121551150412155115041215511504121551150412155115041215511504121551150412155115041215511504121551150412155115041215511504121551150412155115041215511504121551150412155115041215511504121551150412155115041215511504121551150412155115".to_string()).unwrap();
        assert_eq!(guess_xor_keylen(&cipher, 2), vec![5, 10]);
    }

    #[test]
    fn test_guess_xor_short() {
        let cipher = hex2bytes("380a05111015091f581000170607445404531255034953105f5412011b5e1345071b101a0a1d111e7e".to_string()).unwrap();
        let possible_keys = guess_xor(&cipher);
        assert_eq!(possible_keys.iter()
                   .filter(|k| k.as_slice() == b"test0").count(), 1);
    }

    #[test]
    fn test_guess_xor_long() {
        let file = File::open("data/6.txt").unwrap();
        let mut cipher: Vec<u8> = Vec::new();
        for line in BufReader::new(file).lines() {
            let l = line.unwrap();
            cipher.append(&mut b64::decode(l.trim_right().as_bytes()).unwrap());
        }
        let possible_keys = guess_xor(&cipher);
        assert_eq!(possible_keys[0].as_slice(), b"Terminator X: Bring the noise");
        // let k = String::from_utf8(key).unwrap();
    }

}
