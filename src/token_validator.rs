// SPDX-License-Identifier: Apache-2.0
//! Constant-time bearer-token validation (parity Block E, #340).
//!
//! Port of iicp-adapter `services/token_validator.py`. Compares a presented token against
//! the expected one in constant time (via the `subtle` crate, already a dependency for
//! pricing HMAC) so a timing side-channel can't recover the token byte-by-byte. The
//! expected token is updated after registration.

use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Default)]
pub struct TokenValidator {
    expected: String,
}

impl TokenValidator {
    pub fn new(expected_token: impl Into<String>) -> Self {
        Self {
            expected: expected_token.into(),
        }
    }

    pub fn is_valid(&self, presented: &str) -> bool {
        if self.expected.is_empty() || presented.is_empty() {
            return false;
        }
        let a = self.expected.as_bytes();
        let b = presented.as_bytes();
        // Length is not secret; guard before the constant-time compare (ct_eq needs
        // equal-length slices to be meaningful).
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Set the expected token after registration (directory-issued).
    pub fn update_token(&mut self, new_token: impl Into<String>) {
        self.expected = new_token.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_expected_rejects() {
        assert!(!TokenValidator::default().is_valid("x"));
    }

    #[test]
    fn matching_accepted_mismatch_rejected() {
        let v = TokenValidator::new("secret-123");
        assert!(v.is_valid("secret-123"));
        assert!(!v.is_valid("secret-456"));
        assert!(!v.is_valid(""));
    }

    #[test]
    fn update_token_after_registration() {
        let mut v = TokenValidator::new("old");
        v.update_token("new");
        assert!(v.is_valid("new"));
        assert!(!v.is_valid("old"));
    }
}
