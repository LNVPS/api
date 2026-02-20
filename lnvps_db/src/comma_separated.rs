use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A wrapper around `Vec<T>` that serialises to/from a comma-separated string
/// when stored in a SQL column.
///
/// # Decode
/// The column value is split on `','`, each token is trimmed, and `T::from_str`
/// is called on each non-empty token.
///
/// # Encode
/// Each element is formatted with `Display` and joined with `','`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommaSeparated<T>(pub Vec<T>);

impl<T> Default for CommaSeparated<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> CommaSeparated<T> {
    pub fn new(inner: Vec<T>) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T> From<Vec<T>> for CommaSeparated<T> {
    fn from(v: Vec<T>) -> Self {
        Self(v)
    }
}

impl<T> From<CommaSeparated<T>> for Vec<T> {
    fn from(cs: CommaSeparated<T>) -> Self {
        cs.0
    }
}

impl<T> Deref for CommaSeparated<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for CommaSeparated<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Display> Display for CommaSeparated<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for item in &self.0 {
            if !first {
                f.write_str(",")?;
            }
            write!(f, "{item}")?;
            first = false;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// sqlx MySQL implementation
// ---------------------------------------------------------------------------
#[cfg(feature = "mysql")]
mod mysql_impl {
    use super::*;
    use sqlx::error::BoxDynError;
    use sqlx::mysql::{MySql, MySqlTypeInfo, MySqlValueRef};
    use sqlx::{Decode, Encode, Type};

    impl<T> Type<MySql> for CommaSeparated<T> {
        fn type_info() -> MySqlTypeInfo {
            <String as Type<MySql>>::type_info()
        }

        fn compatible(ty: &MySqlTypeInfo) -> bool {
            <String as Type<MySql>>::compatible(ty)
        }
    }

    impl<'r, T> Decode<'r, MySql> for CommaSeparated<T>
    where
        T: FromStr,
        T::Err: Display,
    {
        fn decode(value: MySqlValueRef<'r>) -> Result<Self, BoxDynError> {
            use sqlx::ValueRef;
            // Handle NULL as empty list
            if value.is_null() {
                return Ok(CommaSeparated(Vec::new()));
            }
            let raw = <String as Decode<MySql>>::decode(value)?;
            if raw.is_empty() {
                return Ok(CommaSeparated(Vec::new()));
            }
            let items = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| T::from_str(s).map_err(|e| -> BoxDynError { e.to_string().into() }))
                .collect::<Result<Vec<T>, BoxDynError>>()?;
            Ok(CommaSeparated(items))
        }
    }

    impl<'q, T> Encode<'q, MySql> for CommaSeparated<T>
    where
        T: Display,
    {
        fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<sqlx::encode::IsNull, BoxDynError> {
            let encoded = self.to_string();
            <String as Encode<MySql>>::encode_by_ref(&encoded, buf)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_empty() {
        let cs: CommaSeparated<u32> = CommaSeparated::new(vec![]);
        assert_eq!(cs.to_string(), "");
    }

    #[test]
    fn display_single() {
        let cs = CommaSeparated::new(vec![42u32]);
        assert_eq!(cs.to_string(), "42");
    }

    #[test]
    fn display_multiple() {
        let cs = CommaSeparated::new(vec![1u32, 2, 3]);
        assert_eq!(cs.to_string(), "1,2,3");
    }

    #[test]
    fn from_vec_and_into_vec() {
        let v = vec![10u32, 20, 30];
        let cs = CommaSeparated::from(v.clone());
        let back: Vec<u32> = cs.into();
        assert_eq!(back, v);
    }

    #[test]
    fn deref_as_slice() {
        let cs = CommaSeparated::new(vec![1u32, 2, 3]);
        assert_eq!(cs.len(), 3);
        assert_eq!(cs[1], 2);
    }

    #[test]
    fn parse_via_from_str_roundtrip() {
        // Simulate what Decode does: split + T::from_str
        let raw = "10,20,30";
        let items: Vec<u32> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u32>().unwrap())
            .collect();
        let cs = CommaSeparated::new(items);
        assert_eq!(cs.to_string(), raw);
    }

    #[test]
    fn parse_empty_string() {
        let raw = "";
        let items: Vec<u32> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u32>().unwrap())
            .collect();
        assert!(items.is_empty());
    }

    #[test]
    fn parse_with_spaces() {
        let raw = " 1 , 2 , 3 ";
        let items: Vec<u32> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u32>().unwrap())
            .collect();
        let cs = CommaSeparated::new(items);
        assert_eq!(cs.to_string(), "1,2,3");
    }
}
