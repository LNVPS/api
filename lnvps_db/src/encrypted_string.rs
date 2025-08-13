use crate::encryption::EncryptionContext;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::{Decode, Encode, Type};
use std::fmt::{self, Debug, Display};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper type that automatically encrypts/decrypts strings for database storage
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedString {
    plaintext: String,
}

impl EncryptedString {
    /// Create a new EncryptedString from plaintext
    pub fn new(plaintext: String) -> Self {
        Self { plaintext }
    }

    /// Get the plaintext value
    pub fn as_str(&self) -> &str {
        &self.plaintext
    }

    /// Check if the encrypted string is empty
    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }

    /// Get the length of the plaintext
    pub fn len(&self) -> usize {
        self.plaintext.len()
    }
}

impl From<String> for EncryptedString {
    fn from(plaintext: String) -> Self {
        Self::new(plaintext)
    }
}

impl From<&str> for EncryptedString {
    fn from(plaintext: &str) -> Self {
        Self::new(plaintext.to_owned())
    }
}

impl From<&String> for EncryptedString {
    fn from(plaintext: &String) -> Self {
        Self::new(plaintext.clone())
    }
}

impl From<EncryptedString> for String {
    fn from(encrypted: EncryptedString) -> Self {
        encrypted.plaintext.clone()
    }
}

impl AsRef<str> for EncryptedString {
    fn as_ref(&self) -> &str {
        &self.plaintext
    }
}

impl Display for EncryptedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ENCRYPTED]")
    }
}

impl Debug for EncryptedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptedString([ENCRYPTED])")
    }
}

// SQLx MySQL implementation
#[cfg(feature = "mysql")]
mod mysql_impl {
    use super::*;
    use sqlx::error::BoxDynError;
    use sqlx::mysql::{MySql, MySqlValueRef};

    impl Type<MySql> for EncryptedString {
        fn type_info() -> sqlx::mysql::MySqlTypeInfo {
            <String as Type<MySql>>::type_info()
        }

        fn compatible(ty: &sqlx::mysql::MySqlTypeInfo) -> bool {
            <String as Type<MySql>>::compatible(ty)
        }
    }

    impl<'r> Decode<'r, MySql> for EncryptedString {
        fn decode(value: MySqlValueRef<'r>) -> Result<Self, BoxDynError> {
            let stored_value = <String as Decode<MySql>>::decode(value)?;

            // Check if the value is already encrypted
            if EncryptionContext::is_encrypted(&stored_value) {
                // Decrypt the encrypted value
                let context = EncryptionContext::get()
                    .map_err(|e| format!("Encryption context not initialized: {}", e))?;

                let plaintext = context
                    .decrypt(&stored_value)
                    .map_err(|e| format!("Failed to decrypt string: {}", e))?;

                Ok(EncryptedString::new(plaintext))
            } else {
                // During migration period: treat as plaintext
                // This allows gradual migration without breaking existing data
                Ok(EncryptedString::new(stored_value))
            }
        }
    }

    impl<'q> Encode<'q, MySql> for EncryptedString {
        fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<sqlx::encode::IsNull, BoxDynError> {
            // Try to get encryption context
            match EncryptionContext::get() {
                Ok(context) => {
                    // Encryption is configured, encrypt the string
                    let encrypted_base64 =
                        context
                            .encrypt(&self.plaintext)
                            .map_err(|e| -> BoxDynError {
                                format!("Failed to encrypt string: {}", e).into()
                            })?;

                    <String as Encode<MySql>>::encode_by_ref(&encrypted_base64, buf)
                }
                Err(_) => {
                    // Encryption not configured, store as plain text
                    <String as Encode<MySql>>::encode_by_ref(&self.plaintext, buf)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::EncryptionContext;
    use tempfile::tempdir;

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup_encryption_context() {
        INIT.call_once(|| {
            let temp_file = tempdir().unwrap().path().join("test_key.key");
            let _ = EncryptionContext::try_init_from_file(temp_file, true); // Ignore result to avoid panics
        });
    }

    #[test]
    fn test_encrypted_string_basic() {
        setup_encryption_context();
        let plaintext = "Hello, World!";
        let encrypted = EncryptedString::new(plaintext.to_string());

        assert_eq!(encrypted.as_str(), plaintext);
        assert_eq!(encrypted.len(), plaintext.len());
        assert!(!encrypted.is_empty());
    }

    #[test]
    fn test_encrypted_string_conversion() {
        setup_encryption_context();
        let plaintext = "Test string";

        // Test From<String>
        let encrypted1 = EncryptedString::from(plaintext.to_string());
        assert_eq!(encrypted1.as_str(), plaintext);

        // Test From<&str>
        let encrypted2 = EncryptedString::from(plaintext);
        assert_eq!(encrypted2.as_str(), plaintext);

        // Test Into<String>
        let string_back: String = encrypted1.into();
        assert_eq!(string_back, plaintext);
    }

    #[test]
    fn test_encrypted_string_display() {
        setup_encryption_context();
        let encrypted = EncryptedString::new("secret".to_string());
        assert_eq!(format!("{}", encrypted), "[ENCRYPTED]");
        assert_eq!(format!("{:?}", encrypted), "EncryptedString([ENCRYPTED])");
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_encode_decode_with_encryption() {
        setup_encryption_context();

        let plaintext = "Test secret data";
        let _encrypted = EncryptedString::new(plaintext.to_string());

        // Create a test MySQL buffer to simulate encoding
        // This is a simplified test - in practice, this would go through SQLx's full encoding pipeline
        let context = EncryptionContext::get().unwrap();
        let encrypted_base64 = context.encrypt(plaintext).unwrap();
        let decrypted_plaintext = context.decrypt(&encrypted_base64).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
    }
}
