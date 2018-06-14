//! # Salsa20
//!
//! `salsa20` implements the Salsa20 stream cipher.
//! Salsa20 is a hash function that can be used in
//! counter mode to act as a stream cipher.

fn quarter_round(y: [u32; 4]) -> [u32; 4] {
    let mut z = [0u32; 4];

    z[1] = y[1] ^ (y[0].wrapping_add(y[3]).rotate_left(7));
    z[2] = y[2] ^ (z[1].wrapping_add(y[0]).rotate_left(9));
    z[3] = y[3] ^ (z[2].wrapping_add(z[1]).rotate_left(13));
    z[0] = y[0] ^ (z[3].wrapping_add(z[2]).rotate_left(18));

    z
}

fn row_round(y: [u32; 16]) -> [u32; 16] {
    let [z0, z1, z2, z3] = quarter_round([y[0], y[1], y[2], y[3]]);
    let [z5, z6, z7, z4] = quarter_round([y[5], y[6], y[7], y[4]]);
    let [z10, z11, z8, z9] = quarter_round([y[10], y[11], y[8], y[9]]);
    let [z15, z12, z13, z14] = quarter_round([y[15], y[12], y[13], y[14]]);

    [
        z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_round_spec() {
        assert_eq!([0, 0, 0, 0], quarter_round([0, 0, 0, 0]));
        assert_eq!(
            [0x08008145, 0x00000080, 0x00010200, 0x20500000],
            quarter_round([0x00000001, 0x00000000, 0x00000000, 0x00000000])
        );
        assert_eq!(
            [0x88000100, 0x00000001, 0x00000200, 0x00402000],
            quarter_round([0x00000000, 0x00000001, 0x00000000, 0x00000000])
        );
        assert_eq!(
            [0x80040000, 0x00000000, 0x00000001, 0x00002000],
            quarter_round([0x00000000, 0x00000000, 0x00000001, 0x00000000])
        );
        assert_eq!(
            [0x00048044, 0x00000080, 0x00010000, 0x20100001],
            quarter_round([0x00000000, 0x00000000, 0x00000000, 0x00000001])
        );
        assert_eq!(
            [0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3],
            quarter_round([0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137])
        );
        assert_eq!(
            [0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c],
            quarter_round([0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b])
        );
    }

    #[test]
    fn row_round_spec() {
        assert_eq!(
            [
                0x08008145, 0x00000080, 0x00010200, 0x20500000, 0x20100001, 0x00048044, 0x00000080,
                0x00010000, 0x00000001, 0x00002000, 0x80040000, 0x00000000, 0x00000001, 0x00000200,
                0x00402000, 0x88000100,
            ],
            row_round([
                0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000,
                0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000,
                0x00000000, 0x00000000,
            ])
        );
        assert_eq!(
            [
                0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86, 0x949d2192, 0x764b7754, 0xe408d9b9,
                0x7a41b4d1, 0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8, 0x0040ede5, 0xb545fbce,
                0xd257ed4f, 0x1818882d,
            ],
            row_round([
                0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365, 0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3,
                0xda0a64f6, 0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e, 0xe859c100, 0xea4d84b7,
                0x0f619bff, 0xbc6e965a,
            ])
        )
    }
}
