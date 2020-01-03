use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Converts a string representing in hex a byte array to an actual byte array
///
/// Returns also the length of bytes read or -1 in case of failure.
pub fn hex2bytes(hex: String) -> Result<Vec<u8>, io::Error> {
    if hex.len() % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Input with odd length",
        ));
    }

    let mut bytes_out: Vec<u8> = Vec::new();

    let mut hi = 0;
    let mut lo;
    for (i, c) in hex.chars().enumerate() {
        if c >= '0' && c <= '9' {
            lo = c as u8 - 0x30;
        } else if c >= 'A' && c <= 'F' {
            lo = c as u8 + 0xa - 0x41;
        } else if c >= 'a' && c <= 'f' {
            lo = c as u8 + 0xa - 0x61;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported character",
            ));
        }

        if i % 2 == 0 {
            hi = lo;
        } else {
            bytes_out.push((hi << 4) + lo);
        }
    }

    Ok(bytes_out)
}

/// Encodes a byte array to a base64 String
pub fn encode(raw: &[u8]) -> String {
    let mut res = String::new();

    for triple in raw.chunks(3) {
        let triple_len = triple.len();

        let mut a = Vec::new();
        a.push((triple[0] & 0b11111100) >> 2);
        a.push((triple[0] & 0b00000011) << 4);
        if triple_len > 1 {
            a[1] += (triple[1] & 0b11110000) >> 4;
            a.push((triple[1] & 0b00001111) << 2);

            if triple_len > 2 {
                a[2] += (triple[2] & 0b11000000) >> 6;
                a.push(triple[2] & 0b00111111);
            }
        }

        for c in a.iter() {
            if *c < 26 {
                res.push((c + 0x41) as char);
            } else if *c < 52 {
                res.push((c - 26 + 0x61) as char);
            } else if *c < 62 {
                res.push((c - 52 + 0x30) as char);
            } else if *c == 62 {
                res.push('+');
            } else if *c == 63 {
                res.push('/');
            } else {
                // we know we only pushed 6-bits octets
            }
        }

        for _ in 0..(3 - triple_len) {
            res.push('=');
        }
    }

    res
}

/// Decodes a base64 String to a byte array
pub fn decode(raw: &[u8]) -> Result<Vec<u8>, io::Error> {
    if raw.len() % 4 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Input with invalid length",
        ));
    }

    let mut res: Vec<u8> = Vec::new();
    for chunk in raw.chunks(4) {
        let four: Vec<u8> = chunk
            .iter()
            .map(|&c| {
                if c >= 'A' as u8 && c <= 'Z' as u8 {
                    Ok(c - 'A' as u8)
                } else if c >= 'a' as u8 && c <= 'z' as u8 {
                    Ok(c - 'a' as u8 + 26)
                } else if c >= '0' as u8 && c <= '9' as u8 {
                    Ok(c - '0' as u8 + 52)
                } else if c == '+' as u8 {
                    Ok(62)
                } else if c == '/' as u8 {
                    Ok(63)
                } else if c == '=' as u8 {
                    Ok(0)
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unsupported character",
                    ));
                }
            })
            .map(|c| c.unwrap())
            .collect();

        res.push(((four[0] & 0b00111111) << 2) + ((four[1] & 0b00110000) >> 4));
        if chunk[2] != '=' as u8 {
            res.push(((four[1] & 0b00001111) << 4) + ((four[2] & 0b00111100) >> 2));
            if chunk[3] != '=' as u8 {
                res.push(((four[2] & 0b00000011) << 6) + (four[3] & 0b00111111));
            }
        }
    }
    Ok(res)
}

pub fn hex2base64(hex: String) -> Result<String, io::Error> {
    let bytes = match hex2bytes(hex) {
        Ok(vec) => vec,
        Err(e) => return Err(e),
    };
    Ok(encode(bytes.as_slice()))
}

pub fn read_file<P: AsRef<Path>>(path: P, out: &mut Vec<u8>) {
    let file = File::open(path).unwrap();
    for line in BufReader::new(file).lines() {
        let l = line.unwrap();
        out.append(&mut decode(l.trim_end().as_bytes()).unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex2bytes_success() {
        assert_eq!(hex2bytes("0099".to_string()).unwrap(), b"\x00\x99".to_vec());
        assert_eq!(hex2bytes("ff00".to_string()).unwrap(), b"\xff\x00".to_vec());
        assert_eq!(hex2bytes("aaAA".to_string()).unwrap(), b"\xaa\xAA".to_vec());
        assert_eq!(
            hex2bytes("abcdef".to_string()).unwrap(),
            b"\xab\xcd\xef".to_vec()
        );
    }

    #[test]
    fn test_hex2bytes_fail() {
        assert_eq!(
            hex2bytes("abcx".to_string()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            hex2bytes("abc".to_string()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn test_encode() {
        assert_eq!(encode(b"\x00hello"), "AGhlbGxv".to_string());
        assert_eq!(encode(b"hello"), "aGVsbG8=".to_string());
        assert_eq!(encode(b"hell"), "aGVsbA==".to_string());
        assert_eq!(encode(b""), "".to_string());
    }

    #[test]
    fn test_hex2base64() {
        assert_eq!(hex2base64("49".to_string()).unwrap(), "SQ==");
        assert_eq!(hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
                              .to_string()).unwrap(),
                   "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(
            hex2base64(
                "0102030405060708090a0b0c0d0e0f101112131415161718191aab1c1d1e1f20".to_string()
            )
            .unwrap(),
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRqrHB0eHyA="
        );
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode(b"AGhlbGxv").unwrap(), b"\x00hello");
        assert_eq!(decode(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode(b"aGVsbA==").unwrap(), b"hell");
        assert_eq!(decode(b"").unwrap(), b"");
    }
}
