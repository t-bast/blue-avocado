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

        instance
    }

    fn init(&mut self) {
        for i in 0..IV_SIZE_BYTES {
            self.r1[i] = self.iv[i];
        }

        for i in 0..KEY_SIZE_BYTES {
            self.r2[i] = self.key[i]
        }

        self.r3[13] = 14u8;
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
}
