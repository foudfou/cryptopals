/// https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
/// https://tools.ietf.org/html/rfc3174#section-7
/// SHA1, as well as MD5, are built on the model of Merkle–Damgård (MD). MD
/// also stands for "Message Digest".
use std::convert::{TryFrom, TryInto};

use crate::md4::md_padding;

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

/// Authenticate a message with a MAC, given a shared key. MAC =
/// SHA1(key || message).
pub fn sha1_mac_verify(key: &[u8], msg: &[u8], mac: &[u8]) -> bool {
    sha1(&[key, msg].concat()) == mac
}

pub fn sha256(bufs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = openssl::sha::Sha256::new();
    for buf in bufs {
        hasher.update(buf);
    }
    hasher.finish()
}

pub fn sha256_for_hmac(buf: &[u8]) -> Vec<u8> {
    sha256(&[buf]).to_vec()
}

#[cfg(test)]
pub mod tests {
    use crate::sha::*;

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
    fn test_sha1_mac_verify() {
        let msg = b"FOUDIL WAS HERE - 2019-01-08";
        let key = b"iloveyou";
        let mac = sha1(&[key.to_vec(), msg.to_vec()].concat());
        assert!(sha1_mac_verify(key, msg, &mac));

        let msg_altered = b"FOUDIL WAS HERE - 2019-01-09";
        let mac_altered = sha1(&[key.to_vec(), msg_altered.to_vec()].concat());
        assert!(mac_altered != mac);

        let unknown_key = b"";
        let mac_unknown_key = sha1(&[unknown_key.to_vec(), msg.to_vec()].concat());
        assert!(mac_unknown_key != mac);
    }

    #[test]
    fn test_sha256() {
        use crate::b64::hex2bytes;

        let i = &hex2bytes(
            "\
c15494230bdd6746cd5ad01ed08267243c8c474721324386ad65af98d7274666\
48a70153b22677b740befb6b14b9360bc1b0e0b129567a8594b301317c9bb5a4\
d276123f56ee70c5790fb28a8e2b5788d9304a763a473c0cf811519cf00f5e1d\
bf70493a91ecfce9f4cdabe9f9c89dac9c1e774a2030e577767bf78fa5b01926\
ecf921e67a5595ae0e674ab1cfcf545cdbad5f3229550ea204fb007e42ae3a0e\
f80a9629439fd6a903ddefadc4e2a5b948d8b90efbd02c4fc87fad6295428e03\
0883c2052a0d0c7e59ced65198cdac3ced50b55a0e5202e8355f46fb83aa7fc9\
2560b999aad8664dc78ab05afe222e2fa23161e9474c7950a3fd0d5cf3b2d9e0\
01dac3aefc9d27da79439a4f6d3c501bbcf109075e6921e2c20e7327d151a47e\
a0e14f31383bf708687fcbe468d0820052a7eec56b3bb0000032b39b31b2cdc5\
1ecd96416fdda87af5eb913c4d1be205e05f948db1bb609965c1c1cb24b28a7a\
3d4865cbd91ff2765a09ef25687ecf5f02c04f3a47d1c8c71902ba93d28dbde1\
cae6b307abacea87ecd83b059d64eff2f4f49e649b92a1f7363e9de035e55a55\
3f51059dcef4190a2cccd4cf08548e20958cf02e4eb24adc564db8d8285eea06\
7f50322382de44ba0ac90fded5581921306c81b5127205ba74606d20f7fe4627\
83105fe6762d9d9ae63150d46c2c1744c267438a6b3cfa34f12908c66d977f4b\
c0"
            .to_string(),
        )
        .unwrap()[..];

        let got = sha256(&[i]);
        let want = &hex2bytes(
            "88b8e2c8cda021bc570f1ef7670fc1bcd01c69b9c9ca144bccae7367a981955c".to_string(),
        )
        .unwrap()[..];

        assert_eq!(got, want);
    }
}
