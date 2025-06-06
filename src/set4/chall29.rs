#[cfg(test)]
mod tests {
    use rand::prelude::*;
    use std::convert::TryInto;

    use crate::md4::md_padding;
    use crate::sha::*;

    #[test]
    fn test_sha1_beak_keyed_mac_using_length_extension() {
        let mut rng = rand::thread_rng();
        const KEY_LEN_MIN: usize = 6;
        const KEY_LEN_MAX: usize = 32;
        let mut key = [0u8; KEY_LEN_MAX];
        rng.fill_bytes(&mut key);
        let key_len: usize = rng.gen_range(KEY_LEN_MIN..KEY_LEN_MAX + 1);

        let known_msg = b"comment1=cooking%20MCs;userdata=foo;\
                          comment2=%20like%20a%20pound%20of%20bacon"; // len=36+41=77
        let unknown_key = &key[..key_len];
        let new_text = b";admin=true"; // len=11
        let mac = sha1(&[unknown_key.to_vec(), known_msg.to_vec()].concat());
        assert!(sha1_mac_verify(unknown_key, known_msg, &mac));

        // What we want to have is a valid MAC for a string containing
        // new_text, without knowing the key.
        //
        // Recall that SHA1 works by keeping a state that is updated for each
        // block of 512 bits of input. Meaning that we should be able to use a
        // valid SHA1 MAC as the input state to compute additional bytes and
        // obtain a valid MAC.
        //
        // More precisely, given mac1 = SHA1(key || original-message), we want
        // to compute mac2 =
        // SHA1(key || original-message || original-padding || new-text) from
        // mac1. We can do this because mac2 = SHA1_WITH_STATE(new-text,
        // mac1). The only caveat is SHA1_WITH_STATE's padding: it must pad
        // until 512-bits-boundary but end with the length of the complete mac2
        // message: key || original-message || original-padding || new-text.
        //
        // To recap, the forged message will be
        // original-message || original-padding || new-text, and we need to
        // compute mac2. To this end, the only remaining thing is: compute
        // original-padding for key || original-message. And the only unknown
        // is the key length.
        //
        // Note it would be easier if we just had to compute mac2, because then
        // we wouldn't have to compute original-padding, because we'd only need
        // the length of the complete which could easily guess:
        // key || original-message || original-padding is a multiple of 64.
        //
        // Note: *suffixing* the message with the key, HASH(m || k) is a viable
        // option: we would still be able to compute mac2, but we could hardly
        // provide the corresponding forged message:
        // original-message || key || original-padding || new-text. We could
        // try: forged = bla || original-padding || new-text, such that
        // HASH(forged) collides with mac2 (birthday attack).
        //
        // « However, the big advantage of HMAC over H(m||k) is that
        // collision-resistance of the underlying hashing function is not
        // needed. » https://crypto.stackexchange.com/a/5726

        // rfc2104 HMAC Feb 1997 (!) defines HMAC as H(K XOR opad, H(K XOR
        // ipad, text)), ipad = 0x36 repeated B times, opad = the byte 0x5C
        // repeated B times.

        let s = [
            u32::from_be_bytes(mac[0..4].try_into().unwrap()),
            u32::from_be_bytes(mac[4..8].try_into().unwrap()),
            u32::from_be_bytes(mac[8..12].try_into().unwrap()),
            u32::from_be_bytes(mac[12..16].try_into().unwrap()),
            u32::from_be_bytes(mac[16..20].try_into().unwrap()),
        ];

        for l in KEY_LEN_MIN..KEY_LEN_MAX + 1 {
            let mac_msg_len = l + known_msg.len();
            let mac_msg_pad = md_padding(mac_msg_len, bit_len_be_bytes);

            let new_text_pad = md_padding(new_text.len(), bit_len_be_bytes);
            let new_text_with_fake_pad = [
                &new_text[..],
                &new_text_pad[..(new_text_pad.len() - 8)],
                &bit_len_be_bytes(mac_msg_len + mac_msg_pad.len() + new_text.len()),
            ]
            .concat();
            let forged_mac = sha1_with(&new_text_with_fake_pad, s);

            let forged_msg = [&known_msg[..], &mac_msg_pad, &new_text[..]].concat();

            if sha1_mac_verify(unknown_key, &forged_msg, &forged_mac) {
                return;
            }
        }

        panic!("Couldn't forge MAC");
    }
}
