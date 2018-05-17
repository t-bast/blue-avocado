//! # Trivium
//!
//! `trivium` implements the trivium stream cipher.
//! This cipher is meant for hardware implementations, so this software
//! implementation will not be as efficient as it could be.
//! For real applications a software stream cipher should be used
//! (such as Salsa20).

#[cfg(test)]
mod tests {
    #[test]
    fn hello() {
        assert_eq!(24, 24);
    }
}
