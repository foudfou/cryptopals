/// https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
/// https://tools.ietf.org/html/rfc3174#section-7
/// SHA1, as well as MD5, are built on the model of Merkle–Damgård (MD). MD
/// also stands for "Message Digest".
use std::convert::{TryFrom, TryInto};

use md4::md_padding;

/// Although the standard accepts messages of any length < 2^64 bits, we'll
/// consider a byte-based inputs.
pub fn sha1(input: &[u8]) -> Vec<u8> {
    let pad = md_padding(input.len(), bit_len_be_bytes);
    let padded = [input, &pad].concat();

    sha1_with(
        &padded,
        [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
    )
}

/// Sha1 explicitely only allows for messages less than 2**64 bits.
pub fn bit_len_be_bytes(len: usize) -> [u8; 8] {
    u64::try_from(len * 8).unwrap().to_be_bytes()
}

pub fn sha1_with(padded: &[u8], s: [u32; 5]) -> Vec<u8> {
    let mut h0: u32 = s[0];
    let mut h1: u32 = s[1];
    let mut h2: u32 = s[2];
    let mut h3: u32 = s[3];
    let mut h4: u32 = s[4];

    for block in padded.chunks(64) {
        let mut w = [0u32; 80];
        let ints = block
            .chunks(4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<u32>>();
        w[..16].copy_from_slice(&ints[..16]);

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = if (0..20).contains(&i) {
                ((b & c) | ((!b) & d), 0x5A827999)
            } else if (20..40).contains(&i) {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if (40..60).contains(&i) {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };

            let temp: u32 = (a.rotate_left(5))
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
    ]
    .concat()
}

/// Authenticate a message with a MAC, given a shared key. MAC = SHA1(key || message)
pub fn sha1_msg_auth(msg: &[u8], key: &[u8], mac: &[u8]) -> bool {
    sha1(&[key, msg].concat()) == mac
}

#[cfg(test)]
pub mod tests {
    use sha::*;

    #[test]
    fn test_md_padding() {
        assert_eq!(
            md_padding(0, bit_len_be_bytes),
            b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                .to_vec()
        );

        assert_eq!(
            md_padding(1, bit_len_be_bytes),
            b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08"
                .to_vec()
        );

        assert_eq!(
            md_padding(5, bit_len_be_bytes),
            b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28"
                .to_vec()
        );
    }

    #[test]
    fn test_sha1() {
        let tests = [
            (
                b"abc".to_vec(),
                1,
                b"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
                1,
                b"\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1",
            ),
            (
                b"a".to_vec(),
                1000000,
                b"\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F",
            ),
            (
                b"0123456701234567012345670123456701234567012345670123456701234567".to_vec(),
                10,
                b"\xDE\xA3\x56\xA2\xCD\xDD\x90\xC7\xA7\xEC\xED\xC5\xEB\xB5\x63\x93\x4F\x46\x04\x52",
            ),
        ];

        use std::iter;

        for (base, repeat, expect) in tests.iter() {
            let input = iter::repeat(base.clone())
                .take(*repeat)
                .flatten()
                .collect::<Vec<u8>>();
            let sha = sha1(&input);
            let want = expect.to_vec();
            debug_assert!(
                sha == want,
                "\nFailed on input '{}'\n      got: {:x?}\n expected: {:x?}",
                String::from_utf8_lossy(&base),
                sha,
                want
            );
        }
    }

    #[test]
    fn test_sha1_msg_auth() {
        let msg = b"FOUDIL WAS HERE - 2019-01-08";
        let key = b"iloveyou";
        let mac = sha1(&[key.to_vec(), msg.to_vec()].concat());
        assert!(sha1_msg_auth(msg, key, &mac));

        let msg_altered = b"FOUDIL WAS HERE - 2019-01-09";
        let mac_altered = sha1(&[key.to_vec(), msg_altered.to_vec()].concat());
        assert!(mac_altered != mac);

        let unknown_key = b"";
        let mac_unknown_key = sha1(&[unknown_key.to_vec(), msg.to_vec()].concat());
        assert!(mac_unknown_key != mac);
    }
}
