//! # Salsa20
//!
//! `salsa20` implements the Salsa20 stream cipher.
//! Salsa20 is a hash function that can be used in
//! counter mode to act as a stream cipher.

fn quarter_round(y0: u32, y1: u32, y2: u32, y3: u32) -> (u32, u32, u32, u32) {
    let z1 = y1 ^ (y0.wrapping_add(y3).rotate_left(7));
    let z2 = y2 ^ (z1.wrapping_add(y0).rotate_left(9));
    let z3 = y3 ^ (z2.wrapping_add(z1).rotate_left(13));
    let z0 = y0 ^ (z3.wrapping_add(z2).rotate_left(18));
    (z0, z1, z2, z3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_round_spec() {
        assert_eq!((0, 0, 0, 0), quarter_round(0, 0, 0, 0));
        assert_eq!(
            (0x08008145, 0x00000080, 0x00010200, 0x20500000),
            quarter_round(0x00000001, 0x00000000, 0x00000000, 0x00000000)
        );
        assert_eq!(
            (0x88000100, 0x00000001, 0x00000200, 0x00402000),
            quarter_round(0x00000000, 0x00000001, 0x00000000, 0x00000000)
        );
        assert_eq!(
            (0x80040000, 0x00000000, 0x00000001, 0x00002000),
            quarter_round(0x00000000, 0x00000000, 0x00000001, 0x00000000)
        );
        assert_eq!(
            (0x00048044, 0x00000080, 0x00010000, 0x20100001),
            quarter_round(0x00000000, 0x00000000, 0x00000000, 0x00000001)
        );
        assert_eq!(
            (0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3),
            quarter_round(0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137)
        );
        assert_eq!(
            (0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c),
            quarter_round(0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b)
        );
    }
}
