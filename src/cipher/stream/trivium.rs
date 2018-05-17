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
        let instance = Trivium {
            r1: [0u8; 12],
            r2: [0u8; 11],
            r3: [0u8; 14],
            iv: iv,
            key: key,
        };
        // TODO: initalize and warm-up registers.
        instance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trivium_sets_iv_and_key() {
        let iv: IV = [24u8; IV_SIZE_BYTES];
        let key: Key = [42u8; KEY_SIZE_BYTES];
        let cipher = Trivium::new(iv, key);
        assert_eq!(iv, cipher.iv);
        assert_eq!(key, cipher.key);
    }
}
