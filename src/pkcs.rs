use std;
use std::io;

///! PKCS#7 Padding. PKCS#5 is identical but with a `blocksize` of 8 bytes.
///! The cool thing about these padding is that we can always infer the pad
///! size from the last byte. https://crypto.stackexchange.com/a/31380
pub fn pkcs7_pad(input: &[u8], blocksize: usize) -> Result<Vec<u8>, io::Error> {
    let missing = input.len() % blocksize;
    let padlen = if missing == 0 {
        blocksize
    } else {
        blocksize - missing
    };
    if padlen > std::u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pad length too long",
        ));
    }
    let padchar: u8 = padlen as u8;
    let mut out = input.to_vec();
    let mut pad = vec![padchar; padlen];
    out.append(&mut pad);
    Ok(out)
}

pub fn pkcs7_unpad(input: &[u8]) -> Result<Vec<u8>, io::Error> {
    let last = match input.last() {
        None => return Ok(input.to_vec()),
        Some(el) => el,
    };
    let pad_pos = input.len() - (*last as usize);
    for c in &input[pad_pos..] {
        if c != last {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Pad error"));
        }
    }
    Ok(input[..pad_pos].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_pad() {
        let input = b"YELLOW SUBMARINE";
        let pad20 = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        assert_eq!(pkcs7_pad(input, 20).unwrap(), pad20);
        let pad16 = b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\
                      \x10\x10\x10\x10\x10\x10\x10\x10";
        assert_eq!(pkcs7_pad(input, 16).unwrap(), pad16);
        assert!(pkcs7_pad(input, std::u8::MAX as usize + 1 + input.len()).is_err());
    }

    #[test]
    fn test_pkcs7_unpad() {
        let input = b"YELLOW SUBMARINE";
        let pad16 = b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\
                      \x10\x10\x10\x10\x10\x10\x10\x10";
        assert_eq!(pkcs7_unpad(pad16).unwrap(), input);
    }

    #[test]
    fn test_pkcs7_unpad_fail() {
        let pad = b"YELLOW SUBMARINE\x10\xff\x10";
        assert!(pkcs7_unpad(pad).is_err());
    }

    #[test]
    fn test_pkcs7_unpad_2() {
        let pad = b"ICE ICE BABY\x04\x04\x04\x04";
        assert!(pkcs7_unpad(pad).is_ok());
    }

    #[test]
    fn test_pkcs7_unpad_fail_2() {
        let pad = b"ICE ICE BABY\x05\x05\x05\x05";
        assert!(pkcs7_unpad(pad).is_err());
    }

    #[test]
    fn test_pkcs7_unpad_fail_3() {
        let pad = b"ICE ICE BABY\x01\x02\x03\x04";
        assert!(pkcs7_unpad(pad).is_err());
    }
}
