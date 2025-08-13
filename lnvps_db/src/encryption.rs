use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

/// Global encryption context
static ENCRYPTION_CONTEXT: OnceLock<EncryptionContext> = OnceLock::new();

/// Encryption context that holds the cipher instance
pub struct EncryptionContext {
    cipher: Aes256Gcm,
}

impl EncryptionContext {
    /// Initialize the global encryption context with a key from file
    pub fn init_from_file<P: AsRef<Path>>(key_file: P, auto_generate: bool) -> Result<()> {
        let key = load_or_generate_key(key_file, auto_generate)?;
        let cipher = Aes256Gcm::new(&key);
        let context = EncryptionContext { cipher };

        ENCRYPTION_CONTEXT
            .set(context)
            .map_err(|_| anyhow!("Encryption context already initialized"))?;

        Ok(())
    }

    pub fn try_init_from_file<P: AsRef<Path>>(key_file: P, auto_generate: bool) -> Result<()> {
        if ENCRYPTION_CONTEXT.get().is_some() {
            Ok(())
        } else {
            Self::init_from_file(key_file, auto_generate)
        }
    }

    /// Get the global encryption context
    pub fn get() -> Result<&'static EncryptionContext> {
        ENCRYPTION_CONTEXT
            .get()
            .ok_or_else(|| anyhow!("Encryption context not initialized"))
    }

    /// Encrypt a string and return prefixed base64-encoded result
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext for storage
        let mut result = nonce.to_vec();
        result.extend(&ciphertext);

        // Prefix with "ENC:" to clearly identify encrypted values
        Ok(format!("ENC:{}", STANDARD.encode(result)))
    }

    /// Decrypt a prefixed base64-encoded encrypted string
    pub fn decrypt(&self, encrypted_data: &str) -> Result<String> {
        // Check if the data has the "ENC:" prefix
        let base64_data = if let Some(stripped) = encrypted_data.strip_prefix("ENC:") {
            stripped
        } else {
            bail!("String is not encrypted, cant decrypt")
        };

        let encrypted_bytes = STANDARD
            .decode(base64_data)
            .map_err(|e| anyhow!("Invalid base64 encoding: {}", e))?;

        if encrypted_bytes.len() < 12 {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }

        // Extract nonce (first 12 bytes) and ciphertext (rest)
        let nonce = Nonce::from_slice(&encrypted_bytes[..12]);
        let ciphertext = &encrypted_bytes[12..];

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8 in decrypted data: {}", e))
    }

    /// Check if a string is encrypted (has the ENC: prefix)
    pub fn is_encrypted(data: &str) -> bool {
        data.starts_with("ENC:")
    }
}

/// Load encryption key from file, or generate one if it doesn't exist and auto_generate is true
fn load_or_generate_key<P: AsRef<Path>>(
    key_file: P,
    auto_generate: bool,
) -> Result<Key<Aes256Gcm>> {
    let key_path = key_file.as_ref();

    if key_path.exists() {
        // Load existing key
        let key_bytes =
            fs::read(key_path).map_err(|e| anyhow!("Failed to read encryption key file: {}", e))?;

        if key_bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid key file: expected 32 bytes, got {}",
                key_bytes.len()
            ));
        }

        Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
    } else if auto_generate {
        // Generate new key
        let mut key_bytes = [0u8; 32];
        let mut rng = OsRng::default();
        rng.fill_bytes(&mut key_bytes);

        // Create directory if it doesn't exist
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow!("Failed to create key directory: {}", e))?;
        }

        // Write key to file with restrictive permissions
        fs::write(key_path, &key_bytes)
            .map_err(|e| anyhow!("Failed to write encryption key file: {}", e))?;

        // Set file permissions to 600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(key_path, perms)?;
        }

        log::info!("Generated new encryption key at: {}", key_path.display());
        Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
    } else {
        Err(anyhow!(
            "Encryption key file does not exist and auto-generate is disabled"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;
    use tempfile::tempdir;

    static INIT: Once = Once::new();

    fn setup_encryption_context() {
        INIT.call_once(|| {
            let temp_file = tempdir().unwrap().path().join("test_key.key");
            EncryptionContext::try_init_from_file(temp_file, true).unwrap();
        });
    }

    #[test]
    fn test_encryption_roundtrip() {
        setup_encryption_context();
        let context = EncryptionContext::get().unwrap();
        let plaintext = "Hello, World!";

        let encrypted = context.encrypt(plaintext).unwrap();
        let decrypted = context.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_key_generation() {
        setup_encryption_context();

        // This test verifies that the setup function created a proper key
        // We can't verify the specific temp file since it's created in setup
        let context = EncryptionContext::get().unwrap();

        // Test that we can encrypt and decrypt, which proves the key works
        let test_data = "test key generation";
        let encrypted = context.encrypt(test_data).unwrap();
        let decrypted = context.decrypt(&encrypted).unwrap();
        assert_eq!(test_data, decrypted);
    }

    #[test]
    fn test_different_encryptions_produce_different_results() {
        setup_encryption_context();
        let context = EncryptionContext::get().unwrap();
        let plaintext = "Same message";

        let encrypted1 = context.encrypt(plaintext).unwrap();
        let encrypted2 = context.encrypt(plaintext).unwrap();

        // Should be different due to random nonces
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        assert_eq!(context.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(context.decrypt(&encrypted2).unwrap(), plaintext);
    }
}
