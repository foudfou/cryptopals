use std::io;

/// Converts a string representing in hex a byte array to an actual byte array
///
/// Returns also the length of bytes read or -1 in case of failure.
///
/// FIXME: maybe use of `char` type be more apropriate
fn hex2bytes(hex: String) -> Result<Vec<u8>, io::Error> {
    let bytes_in = hex.as_bytes();
    if bytes_in.len() % 2 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Input with odd length"));
    }

    let mut bytes_out: Vec<u8> = Vec::new();

    let mut hi = 0;
    let mut lo;
    let mut i = 0;
    while i < bytes_in.len() {
        let c = bytes_in[i];
        if c >= 0x30 && c <= 0x39 { // '0'..'9'
            lo = c - 0x30;
        }
        else if c >= 0x41 && c <= 0x46 { // 'A'..'F'
            lo = c + 0xa - 0x41;
        }
        else if c >= 0x61 && c <= 0x66 { // 'a'..'f'
            lo = c + 0xa - 0x61;
        }
        else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported character"));
        }

        if i % 2 == 0 {
            hi = lo;
        }
        else {
            bytes_out.push((hi << 4) + lo);
        }

        i += 1;
    }

    Ok(bytes_out)
}

/// Encodes a byte array to a base64 String
fn bytes2base64(hex: &[u8]) -> String {
    let mut res = String::new();

    for triple in hex.chunks(3) {
        let triple_len = triple.len();

        let mut a = Vec::new();
        a.push((triple[0] & 0b11111100) >> 2);
        a.push(((triple[0] & 0b00000011) << 4));
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
            }
            else if *c < 52 {
                res.push((c - 26 + 0x61) as char);
            }
            else if *c < 62 {
                res.push((c - 52 + 0x30) as char);
            }
            else if *c == 62 {
                res.push('+');
            }
            else if *c == 63 {
                res.push('/');
            }
            else {
                // we know we only pushed 6-bits octets
            }
        }

        for _ in 0..(3 - triple_len) {
            res.push('=');
        }
    }

    res
}

fn hex2base64(hex: String) -> Result<String, io::Error> {
    let bytes = match hex2bytes(hex) {
        Ok(vec) => vec,
        Err(e) => return Err(e),
    };
    Ok(bytes2base64(bytes.as_slice()))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex2bytes_success() {
        assert_eq!(hex2bytes("0099".to_string()).unwrap(), b"\x00\x99".to_vec());
        assert_eq!(hex2bytes("ff00".to_string()).unwrap(), b"\xff\x00".to_vec());
        assert_eq!(hex2bytes("aaAA".to_string()).unwrap(), b"\xaa\xAA".to_vec());
        assert_eq!(hex2bytes("abcdef".to_string()).unwrap(), b"\xab\xcd\xef".to_vec());
    }

    #[test]
    fn test_hex2bytes_fail() {
        assert_eq!(hex2bytes("abcx".to_string()).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(hex2bytes("abc".to_string()).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_bytes2base64() {
        assert_eq!(bytes2base64(b"\x00hello"), "AGhlbGxv".to_string());
        assert_eq!(bytes2base64(b"hello"), "aGVsbG8=".to_string());
        assert_eq!(bytes2base64(b"hell"), "aGVsbA==".to_string());
        assert_eq!(bytes2base64(b""), "".to_string());
    }

    #[test]
    fn test_hex2base64() {
        assert_eq!(hex2base64("49".to_string()).unwrap(), "SQ==");
        assert_eq!(hex2base64("49276d206b696c6c696e6720796f7572\
                               20627261696e206c69736f6e6f757320\
                               6d757368726f6f6d"
                              .to_string()).unwrap(),
                   "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(hex2base64("0102030405060708090a0b0c0d0e0f10\
                               1112131415161718191aab1c1d1e1f20"
                              .to_string()).unwrap(),
                   "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRqrHB0eHyA=");
    }
}
