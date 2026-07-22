use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

/// Global encryption context
static ENCRYPTION_CONTEXT: OnceLock<EncryptionContext> = OnceLock::new();

/// Encryption context that holds the cipher instance
pub struct EncryptionContext {
    cipher: Aes256Gcm,
    /// Identifier for the key currently in use, derived from the key material.
    /// Stored in versioned ciphertexts so the correct key can be selected
    /// during future key rotation.
    key_id: String,
}

/// Current ciphertext format version
const FORMAT_VERSION: u8 = 1;

/// Derive a short, non-secret identifier for a key: first 4 bytes of
/// SHA-256(key) as lowercase hex. Identifies a key without revealing it.
fn derive_key_id(key: &Key<Aes256Gcm>) -> String {
    let hash = Sha256::digest(key);
    hash[..4].iter().map(|b| format!("{b:02x}")).collect()
}

impl EncryptionContext {
    /// Initialize the global encryption context with a hex-encoded key
    /// (64 hex chars = 32 bytes). Typically sourced from an environment
    /// variable via the config file.
    pub fn init_from_hex(hex_key: &str) -> Result<()> {
        let key = decode_hex_key(hex_key)?;
        Self::init_with_key(key)
    }

    /// Initialize from hex key, ignoring if already initialized
    pub fn try_init_from_hex(hex_key: &str) -> Result<()> {
        if ENCRYPTION_CONTEXT.get().is_some() {
            Ok(())
        } else {
            Self::init_from_hex(hex_key)
        }
    }

    /// Initialize the global encryption context with a key from file
    pub fn init_from_file<P: AsRef<Path>>(key_file: P, auto_generate: bool) -> Result<()> {
        let key = load_or_generate_key(key_file, auto_generate)?;
        Self::init_with_key(key)
    }

    fn init_with_key(key: Key<Aes256Gcm>) -> Result<()> {
        let cipher = Aes256Gcm::new(&key);
        let key_id = derive_key_id(&key);
        let context = EncryptionContext { cipher, key_id };

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

        // Versioned format: ENC1:<key-id>:<base64(nonce || ciphertext)>
        // The key id allows selecting the correct key when rotating keys.
        Ok(format!(
            "ENC{}:{}:{}",
            FORMAT_VERSION,
            self.key_id,
            STANDARD.encode(result)
        ))
    }

    /// Decrypt an encrypted string, supporting both the current versioned
    /// format (`ENC1:<key-id>:<data>`) and the legacy unversioned `ENC:<data>`
    /// format written before key ids existed.
    pub fn decrypt(&self, encrypted_data: &str) -> Result<String> {
        let base64_data = if let Some(rest) = encrypted_data.strip_prefix("ENC1:") {
            let (key_id, data) = rest
                .split_once(':')
                .ok_or_else(|| anyhow!("Malformed ENC1 ciphertext: missing key id separator"))?;
            if key_id != self.key_id {
                bail!(
                    "Ciphertext was encrypted with key id '{}' but the loaded key has id '{}'",
                    key_id,
                    self.key_id
                );
            }
            data
        } else if let Some(stripped) = encrypted_data.strip_prefix("ENC:") {
            // Legacy format: no key id, assume the loaded key
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

    /// Check if a string is encrypted (has an `ENC:`/`ENC1:` prefix)
    pub fn is_encrypted(data: &str) -> bool {
        data.starts_with("ENC:") || data.starts_with("ENC1:")
    }

    /// Check if a string uses the legacy unversioned format and should be
    /// re-encrypted to embed the key id
    pub fn is_legacy_format(data: &str) -> bool {
        data.starts_with("ENC:")
    }
}

/// Decode a hex-encoded 32-byte encryption key
fn decode_hex_key(hex_key: &str) -> Result<Key<Aes256Gcm>> {
    let key_bytes =
        hex::decode(hex_key.trim()).map_err(|e| anyhow!("Invalid hex in encryption key: {}", e))?;
    if key_bytes.len() != 32 {
        bail!(
            "Invalid encryption key: expected 32 bytes (64 hex chars), got {}",
            key_bytes.len()
        );
    }
    Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
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
        let mut rng = OsRng;
        rng.fill_bytes(&mut key_bytes);

        // Create directory if it doesn't exist
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow!("Failed to create key directory: {}", e))?;
        }

        // Write key to file with restrictive permissions
        fs::write(key_path, key_bytes)
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

    fn create_test_context() -> Result<EncryptionContext> {
        let mut rng = OsRng;
        let mut new_key: [u8; 32] = [0; 32];
        rng.fill_bytes(&mut new_key);
        let key = *Key::<Aes256Gcm>::from_slice(&new_key);
        let cipher = Aes256Gcm::new(&key);
        let key_id = derive_key_id(&key);
        Ok(EncryptionContext { cipher, key_id })
    }

    #[test]
    fn test_local_encryption_roundtrip() {
        // Test encryption/decryption without using global state
        let context = create_test_context().unwrap();

        let plaintext = "Hello, World!";
        let encrypted = context.encrypt(plaintext).unwrap();
        let decrypted = context.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_local_different_encryptions_produce_different_results() {
        // Test that multiple encryptions of same data produce different results
        let context = create_test_context().unwrap();

        let plaintext = "Same message";
        let encrypted1 = context.encrypt(plaintext).unwrap();
        let encrypted2 = context.encrypt(plaintext).unwrap();

        // Should be different due to random nonces
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        assert_eq!(context.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(context.decrypt(&encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn test_is_encrypted_detection() {
        assert!(EncryptionContext::is_encrypted("ENC:some_base64_data"));
        assert!(EncryptionContext::is_encrypted(
            "ENC1:deadbeef:some_base64_data"
        ));
        assert!(!EncryptionContext::is_encrypted("plain_text_data"));
        assert!(!EncryptionContext::is_encrypted(""));
    }

    #[test]
    fn test_versioned_format_contains_key_id() {
        let context = create_test_context().unwrap();
        let encrypted = context.encrypt("secret").unwrap();

        assert!(encrypted.starts_with("ENC1:"));
        assert!(encrypted.starts_with(&format!("ENC1:{}:", context.key_id)));
        assert_eq!(context.key_id.len(), 8); // 4 bytes as hex
    }

    #[test]
    fn test_derive_key_id_is_stable() {
        let key = *Key::<Aes256Gcm>::from_slice(&[42u8; 32]);
        assert_eq!(derive_key_id(&key), derive_key_id(&key));
        let other_key = *Key::<Aes256Gcm>::from_slice(&[43u8; 32]);
        assert_ne!(derive_key_id(&key), derive_key_id(&other_key));
    }

    #[test]
    fn test_decrypt_legacy_format() {
        // Decrypt a ciphertext written in the legacy `ENC:<base64>` format
        let context = create_test_context().unwrap();
        let plaintext = "legacy secret";

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = context
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend(&ciphertext);
        let legacy = format!("ENC:{}", STANDARD.encode(blob));

        assert!(EncryptionContext::is_legacy_format(&legacy));
        assert!(!EncryptionContext::is_legacy_format(
            &context.encrypt(plaintext).unwrap()
        ));
        assert_eq!(context.decrypt(&legacy).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_id_fails() {
        let context = create_test_context().unwrap();
        let other = create_test_context().unwrap();
        let encrypted = context.encrypt("secret").unwrap();

        let err = other.decrypt(&encrypted).unwrap_err();
        assert!(err.to_string().contains("encrypted with key id"));
    }

    #[test]
    fn test_decode_hex_key() {
        let key = decode_hex_key(&"ab".repeat(32)).unwrap();
        assert_eq!(key.as_slice(), &[0xabu8; 32]);
        // Uppercase hex is accepted
        assert!(decode_hex_key(&"AB".repeat(32)).is_ok());
        // Wrong length
        assert!(decode_hex_key("abcd").is_err());
        // Invalid hex characters
        assert!(decode_hex_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn test_init_from_hex_key_id_matches() {
        // A hex key must produce the same context (and key id) as the raw key
        let hex_key = "42".repeat(32);
        let raw = *Key::<Aes256Gcm>::from_slice(&[0x42u8; 32]);
        assert_eq!(
            derive_key_id(&decode_hex_key(&hex_key).unwrap()),
            derive_key_id(&raw)
        );
    }

    #[test]
    fn test_decrypt_malformed_enc1_fails() {
        let context = create_test_context().unwrap();
        let err = context.decrypt("ENC1:nokeyid").unwrap_err();
        assert!(err.to_string().contains("Malformed ENC1"));
    }
}
