//! Password hashing and verification utilities.
//!
//! Uses Argon2id for secure password hashing.

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

/// Hash a password using Argon2id.
///
/// Returns the PHC-formatted hash string suitable for storage.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a stored hash.
///
/// Returns true if the password matches.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Generate a secure random token for email verification.
///
/// Returns a URL-safe base64-encoded string.
pub fn generate_verification_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("Failed to generate random bytes");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "my-secure-password-123!";
        let hash = hash_password(password).expect("Failed to hash password");

        // Hash should be PHC format starting with $argon2
        assert!(hash.starts_with("$argon2"));

        // Verification should succeed with correct password
        assert!(verify_password(password, &hash));

        // Verification should fail with wrong password
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn test_hash_produces_different_salts() {
        let password = "same-password";
        let hash1 = hash_password(password).expect("Failed to hash");
        let hash2 = hash_password(password).expect("Failed to hash");

        // Same password should produce different hashes (different salts)
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(verify_password(password, &hash1));
        assert!(verify_password(password, &hash2));
    }

    #[test]
    fn test_verify_invalid_hash_format() {
        // Invalid hash formats should return false, not panic
        assert!(!verify_password("password", "not-a-valid-hash"));
        assert!(!verify_password("password", ""));
        assert!(!verify_password("password", "$invalid$hash$format"));
    }

    #[test]
    fn test_generate_verification_token() {
        let token1 = generate_verification_token();
        let token2 = generate_verification_token();

        // Tokens should be unique
        assert_ne!(token1, token2);

        // Tokens should be URL-safe (no +, /, or =)
        assert!(!token1.contains('+'));
        assert!(!token1.contains('/'));
        assert!(!token1.contains('='));

        // Token should be ~43 characters (32 bytes base64 encoded)
        assert!(token1.len() >= 40);
    }
}
