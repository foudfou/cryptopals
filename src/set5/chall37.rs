#[cfg(test)]
mod tests {
    use num_bigint::{BigUint, ToBigUint};

    use crate::set5::chall36::*;

    #[test]
    fn test_srp_zero_key() {
        // Same as for DH, if C sends A=0 then S computes Ss=0, and C only has
        // to use Sc=0 to validate authentication.
        srp_proto(Some(BigUint::ZERO), Some(BigUint::ZERO));

        // Same goes for A = any multiple of N (N * anything % N = 0).
        let n = BigUint::parse_bytes(N, 16).unwrap();
        srp_proto(Some(n.clone()), Some(BigUint::ZERO));
        srp_proto(
            Some(2.to_biguint().unwrap() * n.clone()),
            Some(BigUint::ZERO),
        );
    }
}
