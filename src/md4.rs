/// https://tools.ietf.org/html/rfc1320 states: « 32-bit words, where each
/// consecutive group of four bytes is interpreted as a word with the low-order
/// (least significant) byte given first. » that's little-endian.
use std::convert::TryInto;

/// Returns the padding corresponding to `len`.
///
/// According to the standard, the message must be padded to an even 512
/// bits. The first padding bit must be a '1'. The last 64 bits represent the
/// length of the original message. All bits in between should be 0. Aka
/// MD padding.
pub fn md_padding(len: usize, len_to_bytes: fn(usize) -> [u8; 8]) -> Vec<u8> {
    // i1..iN 0x80 0..0 l1..l8 ≡ (l + m + 9) % 64 = 0 = 64 % 64 ≡
    let pad_len = 64 - ((len + 9) % 64);
    let zero_pad = vec![0u8; pad_len as usize];
    let bit_len = len_to_bytes(len);
    [vec![0x80u8], zero_pad, bit_len.to_vec()].concat()
}

// « In the unlikely event that b is greater than 2^64, then only the low-order
// 64 bits of b are used. »
pub fn bit_len_le_bytes(len: usize) -> [u8; 8] {
    let mut res = [0u8; 8];
    let bit_len = len * 8;
    let bytes = bit_len.to_le_bytes();
    res[..].copy_from_slice(&bytes[bytes.len() - 8..bytes.len()]);
    res
}

pub fn md4(input: &[u8]) -> Vec<u8> {
    let pad = md_padding(input.len(), bit_len_le_bytes);
    let padded = [input, &pad].concat();

    md4_with(&padded, [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476])
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Lifted from https://rosettacode.org/wiki/MD4#Rust
// Round 1 macro
// Let [A B C D i s] denote the operation
//   A = (A + f(B,C,D) + X[i]) <<< s
macro_rules! md4round1 {
    ( $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $s:expr, $x:expr) => {{
        // Rust defaults to non-overflowing arithmetic, so we need to specify wrapping add.
        $a = ($a.wrapping_add(f($b, $c, $d)).wrapping_add($x[$i])).rotate_left($s);
    }};
}

// Round 2 macro
// Let [A B C D i s] denote the operation
//   A = (A + g(B,C,D) + X[i] + 5A827999) <<< s .
macro_rules! md4round2 {
    ( $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $s:expr, $x:expr) => {{
        $a = ($a
            .wrapping_add(g($b, $c, $d))
            .wrapping_add($x[$i])
            .wrapping_add(0x5a827999_u32))
        .rotate_left($s);
    }};
}

// Round 3 macro
// Let [A B C D i s] denote the operation
//   A = (A + h(B,C,D) + X[i] + 6ED9EBA1) <<< s .
macro_rules! md4round3 {
    ( $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $s:expr, $x:expr) => {{
        $a = ($a
            .wrapping_add(h($b, $c, $d))
            .wrapping_add($x[$i])
            .wrapping_add(0x6ed9eba1_u32))
        .rotate_left($s);
    }};
}

/** https://tools.ietf.org/html/rfc1320 */
pub fn md4_with(padded: &[u8], s: [u32; 4]) -> Vec<u8> {
    let mut a: u32 = s[0];
    let mut b: u32 = s[1];
    let mut c: u32 = s[2];
    let mut d: u32 = s[3];

    // 16-word block(word = u32)
    for block in padded.chunks(64) {
        let mut x = [0u32; 16];
        let ints = block
            .chunks(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<u32>>();
        x[..].copy_from_slice(&ints[..]);

        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        /* Round 1. */
        md4round1!(a, b, c, d, 0, 3, x); // [A B C D 0 3]
        md4round1!(d, a, b, c, 1, 7, x); // [D A B C 1 7]
        md4round1!(c, d, a, b, 2, 11, x); // [C D A B 2 11]
        md4round1!(b, c, d, a, 3, 19, x); // [B C D A 3 19]
        md4round1!(a, b, c, d, 4, 3, x); // [A B C D 4 3]
        md4round1!(d, a, b, c, 5, 7, x); // [D A B C 5 7]
        md4round1!(c, d, a, b, 6, 11, x); // [C D A B 6 11]
        md4round1!(b, c, d, a, 7, 19, x); // [B C D A 7 19]
        md4round1!(a, b, c, d, 8, 3, x); // [A B C D 8 3]
        md4round1!(d, a, b, c, 9, 7, x); // [D A B C 9 7]
        md4round1!(c, d, a, b, 10, 11, x); // [C D A B 10 11]
        md4round1!(b, c, d, a, 11, 19, x); // [B C D A 11 19]
        md4round1!(a, b, c, d, 12, 3, x); // [A B C D 12 3]
        md4round1!(d, a, b, c, 13, 7, x); // [D A B C 13 7]
        md4round1!(c, d, a, b, 14, 11, x); // [C D A B 14 11]
        md4round1!(b, c, d, a, 15, 19, x); // [B C D A 15 19]

        /* Round 2. */
        md4round2!(a, b, c, d, 0, 3, x); // [A B C D 0  3]
        md4round2!(d, a, b, c, 4, 5, x); // [D A B C 4  5]
        md4round2!(c, d, a, b, 8, 9, x); // [C D A B 8  9]
        md4round2!(b, c, d, a, 12, 13, x); // [B C D A 12 13]
        md4round2!(a, b, c, d, 1, 3, x); // [A B C D 1  3]
        md4round2!(d, a, b, c, 5, 5, x); // [D A B C 5  5]
        md4round2!(c, d, a, b, 9, 9, x); // [C D A B 9  9]
        md4round2!(b, c, d, a, 13, 13, x); // [B C D A 13 13]
        md4round2!(a, b, c, d, 2, 3, x); // [A B C D 2  3]
        md4round2!(d, a, b, c, 6, 5, x); // [D A B C 6  5]
        md4round2!(c, d, a, b, 10, 9, x); // [C D A B 10 9]
        md4round2!(b, c, d, a, 14, 13, x); // [B C D A 14 13]
        md4round2!(a, b, c, d, 3, 3, x); // [A B C D 3  3]
        md4round2!(d, a, b, c, 7, 5, x); // [D A B C 7  5]
        md4round2!(c, d, a, b, 11, 9, x); // [C D A B 11 9]
        md4round2!(b, c, d, a, 15, 13, x); // [B C D A 15 13]

        // [Round 3]
        md4round3!(a, b, c, d, 0, 3, x); // [A B C D 0  3]
        md4round3!(d, a, b, c, 8, 9, x); // [D A B C 8  9]
        md4round3!(c, d, a, b, 4, 11, x); // [C D A B 4  11]
        md4round3!(b, c, d, a, 12, 15, x); // [B C D A 12 15]
        md4round3!(a, b, c, d, 2, 3, x); // [A B C D 2  3]
        md4round3!(d, a, b, c, 10, 9, x); // [D A B C 10 9]
        md4round3!(c, d, a, b, 6, 11, x); // [C D A B 6  11]
        md4round3!(b, c, d, a, 14, 15, x); // [B C D A 14 15]
        md4round3!(a, b, c, d, 1, 3, x); // [A B C D 1  3]
        md4round3!(d, a, b, c, 9, 9, x); // [D A B C 9  9]
        md4round3!(c, d, a, b, 5, 11, x); // [C D A B 5  11]
        md4round3!(b, c, d, a, 13, 15, x); // [B C D A 13 15]
        md4round3!(a, b, c, d, 3, 3, x); // [A B C D 3  3]
        md4round3!(d, a, b, c, 11, 9, x); // [D A B C 11 9]
        md4round3!(c, d, a, b, 7, 11, x); // [C D A B 7  11]
        md4round3!(b, c, d, a, 15, 15, x); // [B C D A 15 15]

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    // Step 5. Output
    [
        a.to_le_bytes(),
        b.to_le_bytes(),
        c.to_le_bytes(),
        d.to_le_bytes(),
    ]
    .concat()
}

/// Authenticate `msg` with `mac`, given `key`.
pub fn md4_mac_verify(msg: &[u8], key: &[u8], mac: &[u8]) -> bool {
    md4(&[key, msg].concat()) == mac
}

#[cfg(test)]
pub mod tests {
    use md4::*;

    #[test]
    fn test_md_padding() {
        assert_eq!(
            md_padding(1, bit_len_le_bytes),
            b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00"
                .to_vec()
        );
    }

    #[test]
    fn test_md4() {
        let tests = [
            (
                b"".to_vec(),
                b"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0",
            ),
            (
                b"a".to_vec(),
                b"\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24",
            ),
            (
                b"abc".to_vec(),
                b"\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d",
            ),
            (
                b"message digest".to_vec(),
                b"\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b",
            ),
            (
                b"abcdefghijklmnopqrstuvwxyz".to_vec(),
                b"\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee\xa8\xed\x63\xdf\x41\x2d\xa9",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
                b"\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                    .to_vec(),
                b"\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f\xcc\x05\x36",
            ),
            (
                b"Rosetta Code".to_vec(),
                b"\xa5\x2b\xcf\xc6\xa0\xd0\xd3\x00\xcd\xc5\xdd\xbf\xbe\xfe\x47\x8b",
            ),
        ];

        for (input, expect) in tests.iter() {
            let md4 = md4(&input);
            let want = expect.to_vec();
            debug_assert!(
                md4 == want,
                "\nFailed on input '{}'\n      got: {:x?}\n expected: {:x?}",
                String::from_utf8_lossy(&input),
                md4,
                want
            );
        }
    }

    #[test]
    fn test_md4_collision() {
        let k1 = b"\x83\x9c\x7a\x4d\x7a\x92\xcb\x56\x78\xa5\xd5\xb9\xee\xa5\xa7\x57\x3c\x8a\x74\xde\xb3\x66\xc3\xdc\x20\xa0\x83\xb6\x9f\x5d\x2a\x3b\xb3\x71\x9d\xc6\x98\x91\xe9\xf9\x5e\x80\x9f\xd7\xe8\xb2\x3b\xa6\x31\x8e\xdd\x45\xe5\x1f\xe3\x97\x08\xbf\x94\x27\xe9\xc3\xe8\xb9";
        let k2 = b"\x83\x9c\x7a\x4d\x7a\x92\xcb\xd6\x78\xa5\xd5\x29\xee\xa5\xa7\x57\x3c\x8a\x74\xde\xb3\x66\xc3\xdc\x20\xa0\x83\xb6\x9f\x5d\x2a\x3b\xb3\x71\x9d\xc6\x98\x91\xe9\xf9\x5e\x80\x9f\xd7\xe8\xb2\x3b\xa6\x31\x8e\xdc\x45\xe5\x1f\xe3\x97\x08\xbf\x94\x27\xe9\xc3\xe8\xb9";
        assert!(md4(k1) == md4(k2));
    }
}
