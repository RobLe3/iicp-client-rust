// SPDX-License-Identifier: Apache-2.0
//! RFC 8785 JSON Canonicalization Scheme support.

use serde_json::Value;
use std::fmt::{Display, Formatter};

pub const JCS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug)]
pub enum JcsError {
    UnsafeInteger,
    Serialization(serde_json::Error),
}

impl Display for JcsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeInteger => write!(
                f,
                "JCS integer exceeds the interoperable IEEE-754 safe range; encode it as a string"
            ),
            Self::Serialization(error) => write!(f, "JCS serialization failed: {error}"),
        }
    }
}

impl std::error::Error for JcsError {}

fn validate(value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                if value.unsigned_abs() > JCS_MAX_SAFE_INTEGER {
                    return Err(JcsError::UnsafeInteger);
                }
            } else if let Some(value) = number.as_u64() {
                if value > JCS_MAX_SAFE_INTEGER {
                    return Err(JcsError::UnsafeInteger);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                validate(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Return RFC 8785 canonical UTF-8 bytes for an interoperable JSON value.
pub fn canonicalize_jcs(value: &Value) -> Result<Vec<u8>, JcsError> {
    validate(value)?;
    serde_jcs::to_vec(value).map_err(JcsError::Serialization)
}
