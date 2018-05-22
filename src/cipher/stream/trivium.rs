//! # Trivium
//!
//! `trivium` implements the trivium stream cipher.
//! This cipher is meant for hardware implementations, so this software
//! implementation will not be as efficient as it could be.
//! For real applications a software stream cipher should be used
//! (such as Salsa20).

/// The size of a private key (in bytes).
pub const KEY_SIZE_BYTES: usize = 10;
/// The size of the initialization vector (in bytes).
pub const IV_SIZE_BYTES: usize = 10;

/// An initialization vector.
pub type IV = [u8; IV_SIZE_BYTES];
/// A symmetric private key.
pub type Key = [u8; KEY_SIZE_BYTES];

/// A Trivium stream cipher.
#[derive(Debug)]
pub struct Trivium {
    r1: [u8; 12], // only the first 93 bits are used
    r2: [u8; 11], // only the first 84 bits are used
    r3: [u8; 14], // only the first 111 bits are used
    iv: IV,
    key: Key,
}

// Public methods.
impl Trivium {
    pub fn new(iv: IV, key: Key) -> Trivium {
        let mut instance = Trivium {
            r1: [0u8; 12],
            r2: [0u8; 11],
            r3: [0u8; 14],
            iv: iv,
            key: key,
        };

        instance.init();
        instance.warm_up();

        instance
    }

    pub fn encrypt(&mut self, message: &[u8]) -> Vec<u8> {
        let mut encrypted: Vec<u8> = Vec::new();

        for (_, b) in message.iter().enumerate() {
            let k = self.clock_byte();
            encrypted.push(b ^ k);
        }

        encrypted
    }

    pub fn decrypt(&mut self, cipher: &[u8]) -> Vec<u8> {
        // Decryption is exactly the same thing as encryption.
        self.encrypt(cipher)
    }
}

// Private methods.
impl Trivium {
    fn init(&mut self) {
        for i in 0..IV_SIZE_BYTES {
            self.r1[i] = self.iv[i];
        }

        for i in 0..KEY_SIZE_BYTES {
            self.r2[i] = self.key[i]
        }

        self.r3[13] = 14u8;
    }

    fn warm_up(&mut self) {
        for _i in 0..1152 {
            self.clock();
        }
    }

    /// clock simulates one clock cycle and returns the key stream bit.
    /// The return value will be either 0 or 1.
    /// This is highly inefficient: the naive implementation has to shift
    /// every byte and compute single-bit results over bytes.
    /// This cipher was really meant for hardware implementations.
    fn clock(&mut self) -> u8 {
        // Register 1
        // Out = XOR(r1[65], r1[92], AND(r1[90], r1[91]))
        let out1: u8 =
            1u8 & (self.r1[8] >> 6 ^ self.r1[11] >> 3 ^ (self.r1[11] >> 4 & self.r1[11] >> 5));

        // Register 2
        // Out = XOR(r2[68], r2[83], AND(r2[81], r2[82]))
        let out2: u8 =
            1u8 & (self.r2[8] >> 3 ^ self.r2[10] >> 4 ^ (self.r2[10] >> 5 & self.r2[10] >> 6));

        // Register 3
        // Out = XOR(r3[65], r3[110], AND(r3[108], r3[109]))
        let out3: u8 =
            1u8 & (self.r3[8] >> 6 ^ self.r3[13] >> 1 ^ (self.r3[13] >> 2 & self.r3[13] >> 3));

        // Register 1
        // In = XOR(out(r3), r1[68])
        let in1: u8 = 1u8 & (out3 ^ self.r1[8] >> 3);

        // Register 2
        // In = XOR(out(r1), r2[77])
        let in2: u8 = 1u8 & (out1 ^ self.r2[9] >> 2);

        // Register 3
        // In = XOR(out(r2), r3[86])
        let in3: u8 = 1u8 & (out2 ^ self.r3[10] >> 1);

        // Shift everything to the right
        Trivium::shift(&mut self.r1);
        Trivium::shift(&mut self.r2);
        Trivium::shift(&mut self.r3);

        // Insert new first bit
        self.r1[0] = (in1 << 7) + self.r1[0];
        self.r2[0] = (in2 << 7) + self.r2[0];
        self.r3[0] = (in3 << 7) + self.r3[0];

        // Return key stream bit
        out1 ^ out2 ^ out3
    }

    /// clock_byte simulates 8 clock cycles and returns a key stream byte.
    fn clock_byte(&mut self) -> u8 {
        let mut b = 0u8;

        for i in 0..8 {
            b |= self.clock() << (7 - i);
        }

        b
    }

    // Shift bytes to the right once.
    fn shift(r: &mut [u8]) {
        let mut carry = 0u8;
        for b in r {
            let new_carry = *b & 1u8;
            *b = (*b >> 1) + (carry << 7);
            carry = new_carry;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const TEST_IV: IV = [24u8; IV_SIZE_BYTES];
    pub const TEST_KEY: Key = [42u8; KEY_SIZE_BYTES];

    #[test]
    fn new_trivium_sets_iv_and_key() {
        let cipher = Trivium::new(TEST_IV, TEST_KEY);
        assert_eq!(TEST_IV, cipher.iv);
        assert_eq!(TEST_KEY, cipher.key);
    }

    #[test]
    fn trivium_init() {
        let mut cipher = Trivium {
            iv: TEST_IV,
            key: TEST_KEY,
            r1: [0u8; 12],
            r2: [0u8; 11],
            r3: [0u8; 14],
        };

        cipher.init();

        assert_eq!(
            [
                24u8, 24u8, 24u8, 24u8, 24u8, 24u8, 24u8, 24u8, 24u8, 24u8, 0u8, 0u8
            ],
            cipher.r1
        );
        assert_eq!(
            [
                42u8, 42u8, 42u8, 42u8, 42u8, 42u8, 42u8, 42u8, 42u8, 42u8, 0u8
            ],
            cipher.r2
        );
        assert_eq!(
            [
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 14u8
            ],
            cipher.r3
        )
    }

    #[test]
    fn new_trivium_warm_up() {
        let cipher = Trivium::new(TEST_IV, TEST_KEY);
        assert_ne!(TEST_IV, &cipher.r1[..IV_SIZE_BYTES]);
        assert_ne!(TEST_KEY, &cipher.r2[..KEY_SIZE_BYTES]);
    }

    #[test]
    fn shift() {
        let mut r = [129u8, 96u8];
        Trivium::shift(&mut r);
        assert_eq!([64u8, 176u8], r);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let mut encrypt_cipher = Trivium::new(TEST_IV, TEST_KEY);
        let encrypted = encrypt_cipher.encrypt("there is no spoon".as_bytes());

        let mut decrypt_cipher = Trivium::new(TEST_IV, TEST_KEY);
        let decrypted = decrypt_cipher.decrypt(&encrypted);

        assert_eq!("there is no spoon".as_bytes(), decrypted.as_slice());
    }
}
