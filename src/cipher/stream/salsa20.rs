//! # Salsa20
//!
//! `salsa20` implements the Salsa20 stream cipher.
//! Salsa20 is a hash function that can be used in
//! counter mode to act as a stream cipher.

/// A Salsa20 stream cipher.
pub struct Salsa20 {
    k0: [u8; 16],
    k1: [u8; 16],
}

impl Salsa20 {
    /// new creates a new Salsa20 cipher with the given key.
    pub fn new(key: [u8; 32]) -> Salsa20 {
        let mut instance = Salsa20 {
            k0: [0u8; 16],
            k1: [0u8; 16],
        };

        for i in 0..16 {
            instance.k0[i] = key[i];
            instance.k1[i] = key[16 + i];
        }

        instance
    }

    /// encrypt a message with a given nonce.
    /// You must make sure you never reuse the same nonce.
    pub fn encrypt(&self, message: &[u8], nonce: [u8; 8]) -> Vec<u8> {
        let l = message.len();

        let mut res = Vec::from(message);
        let mut current = [0u8; 64];

        for i in 0..l {
            if i % 64 == 0 {
                let q = (i / 64) as u64;
                let mut n = [0u8; 16];
                for i in 0..8 {
                    n[i] = nonce[i];
                    n[8 + i] = (q >> (8 * i)) as u8;
                }

                current = key_expansion(self.k0, self.k1, n);
            }

            res[i] = res[i] ^ current[i % 64];
        }

        res
    }

    /// decrypt a cipher with a given nonce.
    /// You must make sure you never reuse the same nonce.
    pub fn decrypt(&self, cipher: &[u8], nonce: [u8; 8]) -> Vec<u8> {
        self.encrypt(cipher, nonce)
    }
}

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

fn column_round(x: [u32; 16]) -> [u32; 16] {
    let [y0, y4, y8, y12] = quarter_round([x[0], x[4], x[8], x[12]]);
    let [y5, y9, y13, y1] = quarter_round([x[5], x[9], x[13], x[1]]);
    let [y10, y14, y2, y6] = quarter_round([x[10], x[14], x[2], x[6]]);
    let [y15, y3, y7, y11] = quarter_round([x[15], x[3], x[7], x[11]]);

    [
        y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15,
    ]
}

fn double_round(x: [u32; 16]) -> [u32; 16] {
    row_round(column_round(x))
}

fn little_endian(b: [u8; 4]) -> u32 {
    b[0] as u32 + ((b[1] as u32) << 8) + ((b[2] as u32) << 16) + ((b[3] as u32) << 24)
}

fn hash(b: [u8; 64]) -> [u8; 64] {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = little_endian([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
    }

    let mut z = x;
    for _ in 0..10 {
        z = double_round(z);
    }

    let mut res = [0u8; 64];
    for i in 0..16 {
        let v = z[i].wrapping_add(x[i]);
        res[4 * i] = v as u8;
        res[4 * i + 1] = (v >> 8) as u8;
        res[4 * i + 2] = (v >> 16) as u8;
        res[4 * i + 3] = (v >> 24) as u8;
    }

    res
}

fn key_expansion(k0: [u8; 16], k1: [u8; 16], n: [u8; 16]) -> [u8; 64] {
    let mut to_hash = [0u8; 64];

    // sigma0
    to_hash[0] = 101;
    to_hash[1] = 120;
    to_hash[2] = 112;
    to_hash[3] = 97;

    for i in 4..20 {
        to_hash[i] = k0[i - 4];
    }

    // sigma1
    to_hash[20] = 110;
    to_hash[21] = 100;
    to_hash[22] = 32;
    to_hash[23] = 51;

    for i in 24..40 {
        to_hash[i] = n[i - 24];
    }

    // sigma2
    to_hash[40] = 50;
    to_hash[41] = 45;
    to_hash[42] = 98;
    to_hash[43] = 121;

    for i in 44..60 {
        to_hash[i] = k1[i - 44];
    }

    // sigma3
    to_hash[60] = 116;
    to_hash[61] = 101;
    to_hash[62] = 32;
    to_hash[63] = 107;

    hash(to_hash)
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
        );
    }

    #[test]
    fn column_round_spec() {
        assert_eq!(
            [
                0x10090288, 0x00000000, 0x00000000, 0x00000000, 0x00000101, 0x00000000, 0x00000000,
                0x00000000, 0x00020401, 0x00000000, 0x00000000, 0x00000000, 0x40a04001, 0x00000000,
                0x00000000, 0x00000000,
            ],
            column_round([
                0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000,
                0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000,
                0x00000000, 0x00000000,
            ])
        );
        assert_eq!(
            [
                0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a, 0x90a20123, 0xead3c4f3, 0x63a091a0,
                0xf0708d69, 0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c, 0x481c2027, 0x53a8e4b5,
                0x4c1f89c5, 0x3f78c9c8,
            ],
            column_round([
                0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365, 0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3,
                0xda0a64f6, 0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e, 0xe859c100, 0xea4d84b7,
                0x0f619bff, 0xbc6e965a,
            ])
        );
    }

    #[test]
    fn double_round_spec() {
        assert_eq!(
            [
                0x8186a22d, 0x0040a284, 0x82479210, 0x06929051, 0x08000090, 0x02402200, 0x00004000,
                0x00800000, 0x00010200, 0x20400000, 0x08008104, 0x00000000, 0x20500000, 0xa0000040,
                0x0008180a, 0x612a8020,
            ],
            double_round([
                0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000,
            ])
        );
        assert_eq!(
            [
                0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0, 0x50440492, 0xf07cad19, 0xae344aa0,
                0xdf4cfdfc, 0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00, 0xa74b2ad6, 0xbc331c5c,
                0x1dda24c7, 0xee928277,
            ],
            double_round([
                0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57, 0xb75540d3, 0x43e93a4c, 0x3a6f2aa0,
                0x726d6b36, 0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11, 0x054bf545, 0x254dd653,
                0xd9421b6d, 0x67b276c1,
            ])
        );
    }

    #[test]
    fn little_endian_spec() {
        assert_eq!(0, little_endian([0, 0, 0, 0]));
        assert_eq!(0x091e4b56, little_endian([86, 75, 30, 9]));
        assert_eq!(0xfaffffff, little_endian([255, 255, 255, 250]));
    }

    #[test]
    fn hash_spec() {
        assert!(
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ].iter()
                .eq(hash([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]).iter())
        );

        assert!(
            [
                109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170, 154, 29,
                29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57, 118, 40, 152,
                157, 180, 57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114, 219, 236, 232, 135, 111,
                155, 110, 18, 24, 232, 95, 158, 179, 19, 48, 202,
            ].iter()
                .eq(hash([
                    211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136, 49,
                    237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207, 31, 240,
                    32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36, 79, 201, 235, 79,
                    3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54,
                ]).iter())
        );

        assert!(
            [
                179, 19, 48, 202, 219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 26, 110,
                170, 154, 109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 69, 144, 51,
                57, 29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 27, 111, 114, 114, 118,
                40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35,
            ].iter()
                .eq(hash([
                    88, 118, 104, 54, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 191,
                    187, 234, 136, 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 86, 16,
                    179, 207, 49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 238, 55, 204,
                    36, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113,
                ]).iter())
        );
    }

    #[test]
    fn key_expansion_spec() {
        let k0: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let k1: [u8; 16] = [
            201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
        ];
        let n: [u8; 16] = [
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        ];

        assert!(
            [
                69, 37, 68, 39, 41, 15, 107, 193, 255, 139, 122, 6, 170, 233, 217, 98, 89, 144,
                182, 106, 21, 51, 200, 65, 239, 49, 222, 34, 215, 114, 40, 126, 104, 197, 7, 225,
                197, 153, 31, 2, 102, 78, 76, 176, 84, 245, 246, 184, 177, 160, 133, 130, 6, 72,
                149, 119, 192, 195, 132, 236, 234, 103, 246, 74,
            ].iter()
                .eq(key_expansion(k0, k1, n).iter())
        );
    }

    #[test]
    fn encrypt_and_decrypt() {
        let mut k = [0u8; 32];
        for i in 0..32 {
            k[i] = i as u8;
        }

        let c = Salsa20::new(k);

        let nonce = [0u8; 8];
        let message = "there is no spoon".as_bytes();
        let cipher = c.encrypt(message, nonce);
        let decrypted = c.decrypt(&cipher, nonce);

        assert_eq!(message, decrypted.as_slice());
    }
}
