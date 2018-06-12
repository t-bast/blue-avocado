//! # Mars
//!
//! `mars` implements the mars block cipher.
//! Mars was one of the AES finalists.

/// A Mars block cipher.
pub struct Mars {
    key: [u32; 40],
}

// Public methods.
impl Mars {
    /// new creates a mars cipher with the given key.
    /// The key needs to contain between 4 and 14 words.
    pub fn new(key: &[u32]) -> Mars {
        if key.len() < 4 || key.len() > 14 {
            panic!("Key length must be between 4 and 14.");
        }

        let mut instance = Mars { key: [0u32; 40] };

        instance.expand_key(key);

        instance
    }

    /// encrypt a block of data.
    pub fn encrypt(&self, a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
        // Forward Mixing.
        let mut a = a.wrapping_add(self.key[0]);
        let mut b = b.wrapping_add(self.key[1]);
        let mut c = c.wrapping_add(self.key[2]);
        let mut d = d.wrapping_add(self.key[3]);

        for i in 0..8 {
            b = (b ^ s0(a)).wrapping_add(s1(a.rotate_right(8)));
            c = c.wrapping_add(s0(a.rotate_right(16)));
            d = d ^ s1(a.rotate_right(24));
            a = a.rotate_right(24);

            if i == 1 || i == 5 {
                a = a.wrapping_add(b);
            }

            if i == 0 || i == 4 {
                a = a.wrapping_add(d);
            }

            let aa = a;
            a = b;
            b = c;
            c = d;
            d = aa;
        }

        // Cryptographic core.
        for i in 0..16 {
            let r = a.rotate_left(13)
                .wrapping_mul(self.key[2 * i + 5])
                .rotate_left(10);
            let m = a.wrapping_add(self.key[2 * i + 4])
                .rotate_left(r.rotate_right(5) % 32);
            let l = (s(m) ^ r.rotate_right(5) ^ r).rotate_left(r % 32);

            if i < 8 {
                b = b.wrapping_add(l);
            } else {
                b = b ^ r;
            }

            c = c.wrapping_add(m);

            if i < 8 {
                d = d ^ r;
            } else {
                d = d.wrapping_add(l);
            }

            let aa = a;
            a = b;
            b = c;
            c = d;
            d = aa.rotate_left(13);
        }

        // Backwards Mixing.
        for i in 0..8 {
            if i == 3 || i == 7 {
                a = a.wrapping_sub(b);
            }

            if i == 2 || i == 6 {
                a = a.wrapping_sub(d);
            }

            b = b ^ s1(a);
            c = c.wrapping_sub(s0(a.rotate_left(8)));
            d = d.wrapping_sub(s1(a.rotate_left(16))) ^ s0(a.rotate_left(24));
            let aa = a;
            a = b;
            b = c;
            c = d;
            d = aa.rotate_left(24);
        }

        a = a.wrapping_sub(self.key[36]);
        b = b.wrapping_sub(self.key[37]);
        c = c.wrapping_sub(self.key[38]);
        d = d.wrapping_sub(self.key[39]);

        (a, b, c, d)
    }

    /// decrypt a block of data.
    pub fn decrypt(&self, a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
        // Forward Mixing.
        let mut a = a.wrapping_add(self.key[36]);
        let mut b = b.wrapping_add(self.key[37]);
        let mut c = c.wrapping_add(self.key[38]);
        let mut d = d.wrapping_add(self.key[39]);

        for i in (0..8).rev() {
            let dd = d;
            d = c;
            c = b;
            b = a;
            a = dd;

            a = a.rotate_right(24);
            d = (d ^ s0(a.rotate_right(8))).wrapping_add(s1(a.rotate_right(16)));
            c = c.wrapping_add(s0(a.rotate_right(24)));
            b = b ^ s1(a);

            if i == 2 || i == 6 {
                a = a.wrapping_add(d);
            }

            if i == 3 || i == 7 {
                a = a.wrapping_add(b);
            }
        }

        // Cryptographic Core.
        for i in (0..16).rev() {
            let dd = d;
            d = c;
            c = b;
            b = a;
            a = dd;

            a = a.rotate_right(13);

            let r = a.rotate_left(13)
                .wrapping_mul(self.key[2 * i + 5])
                .rotate_left(10);
            let m = a.wrapping_add(self.key[2 * i + 4])
                .rotate_left(r.rotate_right(5) % 32);
            let l = (s(m) ^ r.rotate_right(5) ^ r).rotate_left(r % 32);

            if i < 8 {
                b = b.wrapping_sub(l);
            } else {
                b = b ^ r;
            }

            c = c.wrapping_sub(m);

            if i < 8 {
                d = d ^ r;
            } else {
                d = d.wrapping_sub(l);
            }
        }

        // Backwards Mixing.
        for i in (0..8).rev() {
            let dd = d;
            d = c;
            c = b;
            b = a;
            a = dd;

            if i == 0 || i == 4 {
                a = a.wrapping_sub(d);
            }

            if i == 1 || i == 5 {
                a = a.wrapping_sub(b);
            }

            a = a.rotate_left(24);
            d = d ^ s1(a.rotate_right(24));
            c = c.wrapping_sub(s0(a.rotate_right(16)));
            b = b.wrapping_sub(s1(a.rotate_right(8))) ^ s0(a);
        }

        a = a.wrapping_sub(self.key[0]);
        b = b.wrapping_sub(self.key[1]);
        c = c.wrapping_sub(self.key[2]);
        d = d.wrapping_sub(self.key[3]);

        (a, b, c, d)
    }
}

// Private methods.
impl Mars {
    /// Apply the key expansion algorithm.
    fn expand_key(&mut self, key: &[u32]) {
        let mut t = [0u32; 15];
        for i in 0..key.len() {
            t[i] = key[i];
        }

        t[key.len()] = key.len() as u32;

        for j in 0..4 {
            // Linear Key-Word Expansion.
            for i in 0..15 {
                let c1 = (t[(i + 8) % 15] ^ t[(i + 13) % 15]).rotate_left(3);
                let c2 = (4 * i + j) as u32;
                t[i] = t[i] ^ c1 ^ c2;
            }

            // S-box Based Stirring of Key-Words.
            for _ in 0..4 {
                for i in 0..15 {
                    t[i] = (t[i].wrapping_add(s(t[(i + 14) % 15]))).rotate_left(9);
                }
            }

            // Store Next 10 Key-Words into K[].
            for i in 0..10 {
                self.key[10 * j + i] = t[(4 * i) % 15];
            }
        }

        // Modifying Multiplication Key-Words.
        let b: [u32; 4] = [0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978];
        for i in 2..18 {
            let ii = 2 * i + 1;
            let j = (self.key[ii] % 4) as usize;
            let w = self.key[ii] | 3;
            let m = Mars::compute_key_mask(w);
            let r = self.key[ii - 1] % 32;
            let p = b[j].rotate_left(r);
            self.key[ii] = w ^ (p & m);
        }
    }

    /// Compute the word mask used in the key expansion algorithm.
    fn compute_key_mask(w: u32) -> u32 {
        // According to the spec:
        // M = 0
        // M(n) = 1 iff:
        //  * w(n) belongs to a sequence of 10 consecutive 0's or 1's
        //  * 2 <= n <= 30
        //  * w(n-1) == w(n) == w(n+1)
        // In particular, it means that M(0)=M(1)=M(31)=0.

        let mut m = [false; 32];
        for i in 2..31 {
            let prev = (w >> (i - 1)) % 2;
            let cur = (w >> i) % 2;
            let next = (w >> (i + 1)) % 2;

            if cur != prev || cur != next {
                continue;
            }

            // There is most likely a more efficient and more elegant solution than this.
            let mut seq = 1;

            let mut j = i - 1;
            while seq < 10 {
                let tmp = (w >> j) % 2;
                if tmp != cur {
                    break;
                }

                seq += 1;
                if j == 0 {
                    break;
                }

                j -= 1;
            }

            j = i + 1;
            while seq < 10 {
                let tmp = (w >> j) % 2;
                if tmp != cur {
                    break;
                }

                seq += 1;
                if j == 31 {
                    break;
                }

                j += 1;
            }

            if seq >= 10 {
                m[i] = true;
            }
        }

        let mut res = 0;
        for i in 0..32 {
            if m[i] {
                res += 1 << i;
            }
        }

        res
    }
}

/// s discards irrelevant input bits and looks up the S-box.
fn s(i: u32) -> u32 {
    let i: usize = (i % 512) as usize;
    SBOX[i]
}

/// s0 discards irrelevant input bits and looks up the S0-box.
fn s0(i: u32) -> u32 {
    let i: usize = (i % 256) as usize;
    SBOX[i]
}

/// s1 discards irrelevant input bits and looks up the S1-box.
fn s1(i: u32) -> u32 {
    let i: usize = 256 + (i % 256) as usize;
    SBOX[i]
}

/// Magic S-box defined in the specification.
const SBOX: [u32; 512] = [
    0x09d0c479, 0x28c8ffe0, 0x84aa6c39, 0x9dad7287, 0x7dff9be3, 0xd4268361, 0xc96da1d4, 0x7974cc93,
    0x85d0582e, 0x2a4b5705, 0x1ca16a62, 0xc3bd279d, 0x0f1f25e5, 0x5160372f, 0xc695c1fb, 0x4d7ff1e4,
    0xae5f6bf4, 0x0d72ee46, 0xff23de8a, 0xb1cf8e83, 0xf14902e2, 0x3e981e42, 0x8bf53eb6, 0x7f4bf8ac,
    0x83631f83, 0x25970205, 0x76afe784, 0x3a7931d4, 0x4f846450, 0x5c64c3f6, 0x210a5f18, 0xc6986a26,
    0x28f4e826, 0x3a60a81c, 0xd340a664, 0x7ea820c4, 0x526687c5, 0x7eddd12b, 0x32a11d1d, 0x9c9ef086,
    0x80f6e831, 0xab6f04ad, 0x56fb9b53, 0x8b2e095c, 0xb68556ae, 0xd2250b0d, 0x294a7721, 0xe21fb253,
    0xae136749, 0xe82aae86, 0x93365104, 0x99404a66, 0x78a784dc, 0xb69ba84b, 0x04046793, 0x23db5c1e,
    0x46cae1d6, 0x2fe28134, 0x5a223942, 0x1863cd5b, 0xc190c6e3, 0x07dfb846, 0x6eb88816, 0x2d0dcc4a,
    0xa4ccae59, 0x3798670d, 0xcbfa9493, 0x4f481d45, 0xeafc8ca8, 0xdb1129d6, 0xb0449e20, 0x0f5407fb,
    0x6167d9a8, 0xd1f45763, 0x4daa96c3, 0x3bec5958, 0xababa014, 0xb6ccd201, 0x38d6279f, 0x02682215,
    0x8f376cd5, 0x092c237e, 0xbfc56593, 0x32889d2c, 0x854b3e95, 0x05bb9b43, 0x7dcd5dcd, 0xa02e926c,
    0xfae527e5, 0x36a1c330, 0x3412e1ae, 0xf257f462, 0x3c4f1d71, 0x30a2e809, 0x68e5f551, 0x9c61ba44,
    0x5ded0ab8, 0x75ce09c8, 0x9654f93e, 0x698c0cca, 0x243cb3e4, 0x2b062b97, 0x0f3b8d9e, 0x00e050df,
    0xfc5d6166, 0xe35f9288, 0xc079550d, 0x0591aee8, 0x8e531e74, 0x75fe3578, 0x2f6d829a, 0xf60b21ae,
    0x95e8eb8d, 0x6699486b, 0x901d7d9b, 0xfd6d6e31, 0x1090acef, 0xe0670dd8, 0xdab2e692, 0xcd6d4365,
    0xe5393514, 0x3af345f0, 0x6241fc4d, 0x460da3a3, 0x7bcf3729, 0x8bf1d1e0, 0x14aac070, 0x1587ed55,
    0x3afd7d3e, 0xd2f29e01, 0x29a9d1f6, 0xefb10c53, 0xcf3b870f, 0xb414935c, 0x664465ed, 0x024acac7,
    0x59a744c1, 0x1d2936a7, 0xdc580aa6, 0xcf574ca8, 0x040a7a10, 0x6cd81807, 0x8a98be4c, 0xaccea063,
    0xc33e92b5, 0xd1e0e03d, 0xb322517e, 0x2092bd13, 0x386b2c4a, 0x52e8dd58, 0x58656dfb, 0x50820371,
    0x41811896, 0xe337ef7e, 0xd39fb119, 0xc97f0df6, 0x68fea01b, 0xa150a6e5, 0x55258962, 0xeb6ff41b,
    0xd7c9cd7a, 0xa619cd9e, 0xbcf09576, 0x2672c073, 0xf003fb3c, 0x4ab7a50b, 0x1484126a, 0x487ba9b1,
    0xa64fc9c6, 0xf6957d49, 0x38b06a75, 0xdd805fcd, 0x63d094cf, 0xf51c999e, 0x1aa4d343, 0xb8495294,
    0xce9f8e99, 0xbffcd770, 0xc7c275cc, 0x378453a7, 0x7b21be33, 0x397f41bd, 0x4e94d131, 0x92cc1f98,
    0x5915ea51, 0x99f861b7, 0xc9980a88, 0x1d74fd5f, 0xb0a495f8, 0x614deed0, 0xb5778eea, 0x5941792d,
    0xfa90c1f8, 0x33f824b4, 0xc4965372, 0x3ff6d550, 0x4ca5fec0, 0x8630e964, 0x5b3fbbd6, 0x7da26a48,
    0xb203231a, 0x04297514, 0x2d639306, 0x2eb13149, 0x16a45272, 0x532459a0, 0x8e5f4872, 0xf966c7d9,
    0x07128dc0, 0x0d44db62, 0xafc8d52d, 0x06316131, 0xd838e7ce, 0x1bc41d00, 0x3a2e8c0f, 0xea83837e,
    0xb984737d, 0x13ba4891, 0xc4f8b949, 0xa6d6acb3, 0xa215cdce, 0x8359838b, 0x6bd1aa31, 0xf579dd52,
    0x21b93f93, 0xf5176781, 0x187dfdde, 0xe94aeb76, 0x2b38fd54, 0x431de1da, 0xab394825, 0x9ad3048f,
    0xdfea32aa, 0x659473e3, 0x623f7863, 0xf3346c59, 0xab3ab685, 0x3346a90b, 0x6b56443e, 0xc6de01f8,
    0x8d421fc0, 0x9b0ed10c, 0x88f1a1e9, 0x54c1f029, 0x7dead57b, 0x8d7ba426, 0x4cf5178a, 0x551a7cca,
    0x1a9a5f08, 0xfcd651b9, 0x25605182, 0xe11fc6c3, 0xb6fd9676, 0x337b3027, 0xb7c8eb14, 0x9e5fd030,
    0x6b57e354, 0xad913cf7, 0x7e16688d, 0x58872a69, 0x2c2fc7df, 0xe389ccc6, 0x30738df1, 0x0824a734,
    0xe1797a8b, 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978, 0x73398d32, 0x0f59573e, 0xe9df2b03,
    0xe8a5b6c8, 0x848d0704, 0x98df93c2, 0x720a1dc3, 0x684f259a, 0x943ba848, 0xa6370152, 0x863b5ea3,
    0xd17b978b, 0x6d9b58ef, 0x0a700dd4, 0xa73d36bf, 0x8e6a0829, 0x8695bc14, 0xe35b3447, 0x933ac568,
    0x8894b022, 0x2f511c27, 0xddfbcc3c, 0x006662b6, 0x117c83fe, 0x4e12b414, 0xc2bca766, 0x3a2fec10,
    0xf4562420, 0x55792e2a, 0x46f5d857, 0xceda25ce, 0xc3601d3b, 0x6c00ab46, 0xefac9c28, 0xb3c35047,
    0x611dfee3, 0x257c3207, 0xfdd58482, 0x3b14d84f, 0x23becb64, 0xa075f3a3, 0x088f8ead, 0x07adf158,
    0x7796943c, 0xfacabf3d, 0xc09730cd, 0xf7679969, 0xda44e9ed, 0x2c854c12, 0x35935fa3, 0x2f057d9f,
    0x690624f8, 0x1cb0bafd, 0x7b0dbdc6, 0x810f23bb, 0xfa929a1a, 0x6d969a17, 0x6742979b, 0x74ac7d05,
    0x010e65c4, 0x86a3d963, 0xf907b5a0, 0xd0042bd3, 0x158d7d03, 0x287a8255, 0xbba8366f, 0x096edc33,
    0x21916a7b, 0x77b56b86, 0x951622f9, 0xa6c5e650, 0x8cea17d1, 0xcd8c62bc, 0xa3d63433, 0x358a68fd,
    0x0f9b9d3c, 0xd6aa295b, 0xfe33384a, 0xc000738e, 0xcd67eb2f, 0xe2eb6dc2, 0x97338b02, 0x06c9f246,
    0x419cf1ad, 0x2b83c045, 0x3723f18a, 0xcb5b3089, 0x160bead7, 0x5d494656, 0x35f8a74b, 0x1e4e6c9e,
    0x000399bd, 0x67466880, 0xb4174831, 0xacf423b2, 0xca815ab3, 0x5a6395e7, 0x302a67c5, 0x8bdb446b,
    0x108f8fa4, 0x10223eda, 0x92b8b48b, 0x7f38d0ee, 0xab2701d4, 0x0262d415, 0xaf224a30, 0xb3d88aba,
    0xf8b2c3af, 0xdaf7ef70, 0xcc97d3b7, 0xe9614b6c, 0x2baebff4, 0x70f687cf, 0x386c9156, 0xce092ee5,
    0x01e87da6, 0x6ce91e6a, 0xbb7bcc84, 0xc7922c20, 0x9d3b71fd, 0x060e41c6, 0xd7590f15, 0x4e03bb47,
    0x183c198e, 0x63eeb240, 0x2ddbf49a, 0x6d5cba54, 0x923750af, 0xf9e14236, 0x7838162b, 0x59726c72,
    0x81b66760, 0xbb2926c1, 0x48a0ce0d, 0xa6c0496d, 0xad43507b, 0x718d496a, 0x9df057af, 0x44b1bde6,
    0x054356dc, 0xde7ced35, 0xd51a138b, 0x62088cc9, 0x35830311, 0xc96efca2, 0x686f86ec, 0x8e77cb68,
    0x63e1d6b8, 0xc80f9778, 0x79c491fd, 0x1b4c67f2, 0x72698d7d, 0x5e368c31, 0xf7d95e2e, 0xa1d3493f,
    0xdcd9433e, 0x896f1552, 0x4bc4ca7a, 0xa6d1baf4, 0xa5a96dcc, 0x0bef8b46, 0xa169fda7, 0x74df40b7,
    0x4e208804, 0x9a756607, 0x038e87c8, 0x20211e44, 0x8b7ad4bf, 0xc6403f35, 0x1848e36d, 0x80bdb038,
    0x1e62891c, 0x643d2107, 0xbf04d6f8, 0x21092c8c, 0xf644f389, 0x0778404e, 0x7b78adb8, 0xa2c52d53,
    0x42157abe, 0xa2253e2e, 0x7bf3f4ae, 0x80f594f9, 0x953194e7, 0x77eb92ed, 0xb3816930, 0xda8d9336,
    0xbf447469, 0xf26d9483, 0xee6faed5, 0x71371235, 0xde425f73, 0xb4e59f43, 0x7dbe2d4e, 0x2d37b185,
    0x49dc9a63, 0x98c39d98, 0x1301c9a2, 0x389b1bbf, 0x0c18588d, 0xa421c1ba, 0x7aa3865c, 0x71e08558,
    0x3c5cfcaa, 0x7d239ca4, 0x0297d9dd, 0xd7dc2830, 0x4b37802b, 0x7428ab54, 0xaeee0347, 0x4b3fbb85,
    0x692f2f08, 0x134e578e, 0x36d9e0bf, 0xae8b5fcf, 0xedb93ecf, 0x2b27248e, 0x170eb1ef, 0x7dc57fd6,
    0x1e760f16, 0xb1136601, 0x864e1b9b, 0xd7ea7319, 0x3ab871bd, 0xcfa4d76f, 0xe31bd782, 0x0dbeb469,
    0xabb96061, 0x5370f85d, 0xffb07e37, 0xda30d0fb, 0xebc977b6, 0x0b98b40f, 0x3a4d0fe6, 0xdf4fc26b,
    0x159cf22a, 0xc298d6e2, 0x2b78ef6a, 0x61a94ac0, 0xab561187, 0x14eea0f0, 0xdf0d4164, 0x19af70ee,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s_box_0() {
        assert_eq!(0x84aa6c39, s0(0x42424202));
    }

    #[test]
    fn s_box_1() {
        assert_eq!(0x0f59573e, s1(0x4242420E));
    }

    #[test]
    fn s_box() {
        assert_eq!(0x77b56b86, s(0x42424351));
    }

    #[test]
    #[should_panic]
    fn new_key_too_small() {
        Mars::new(&[0u32; 3]);
    }

    #[test]
    #[should_panic]
    fn new_key_too_big() {
        Mars::new(&[0u32; 15]);
    }

    #[test]
    fn new() {
        let instance = Mars::new(&[42u32; 7]);
        assert_ne!(0u32, instance.key[0]);
        assert_ne!(42u32, instance.key[0]);
    }

    #[test]
    fn compute_key_mask() {
        assert_eq!(
            0b01111111111111111111111111111000,
            Mars::compute_key_mask(0b00000000000000000000000000000011)
        );

        assert_eq!(
            0b01111111111000111111110000000000,
            Mars::compute_key_mask(0b00000000000010000000000111111111)
        );
    }

    #[test]
    fn encrypt_and_decrypt() {
        let instance = Mars::new(&[42u32; 14]);
        let (e1, e2, e3, e4) = instance.encrypt(2, 4, 24, 42);
        let (d1, d2, d3, d4) = instance.decrypt(e1, e2, e3, e4);

        assert_eq!(2, d1);
        assert_eq!(4, d2);
        assert_eq!(24, d3);
        assert_eq!(42, d4);
    }
}
