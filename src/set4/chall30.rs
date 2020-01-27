#[cfg(test)]
mod tests {
    use rand::prelude::*;
    use std::convert::TryInto;

    use md4::*;

    #[test]
    fn test_md4_beak_keyed_mac_using_length_extension() {
        //! For explanations see chall29.

        let mut rng = rand::thread_rng();
        const KEY_LEN_MIN: usize = 6;
        const KEY_LEN_MAX: usize = 32;
        let mut key = [0u8; KEY_LEN_MAX];
        rng.fill_bytes(&mut key);
        let key_len: usize = rng.gen_range(KEY_LEN_MIN, KEY_LEN_MAX + 1);

        let known_msg = b"comment1=cooking%20MCs;userdata=foo;\
                          comment2=%20like%20a%20pound%20of%20bacon"; // len=36+41=77
        let unknown_key = &key[..key_len];
        let new_text = b";admin=true"; // len=11
        let mac = md4(&[unknown_key.to_vec(), known_msg.to_vec()].concat());
        assert!(md4_mac_verify(known_msg, unknown_key, &mac));

        let s = [
            u32::from_le_bytes(mac[0..4].try_into().unwrap()),
            u32::from_le_bytes(mac[4..8].try_into().unwrap()),
            u32::from_le_bytes(mac[8..12].try_into().unwrap()),
            u32::from_le_bytes(mac[12..16].try_into().unwrap()),
        ];

        for l in KEY_LEN_MIN..KEY_LEN_MAX + 1 {
            let mac_msg_len = l + known_msg.len();
            let mac_msg_pad = md_padding(mac_msg_len, bit_len_le_bytes);

            let new_text_pad = md_padding(new_text.len(), bit_len_le_bytes);
            let new_text_with_fake_pad = [
                &new_text[..],
                &new_text_pad[..(new_text_pad.len() - 8)],
                &bit_len_le_bytes(mac_msg_len + mac_msg_pad.len() + new_text.len()),
            ]
            .concat();
            let forged_mac = md4_with(&new_text_with_fake_pad, s);

            let forged_msg = [&known_msg[..], &mac_msg_pad, &new_text[..]].concat();

            if md4_mac_verify(&forged_msg, unknown_key, &forged_mac) {
                return;
            }
        }

        panic!("Couldn't forge MAC");
    }
}
