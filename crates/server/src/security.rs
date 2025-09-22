use serde_json::Value;
use std::io::Read;

/// Secure JSON parser with protection against JSON bombs
pub struct SecureJsonParser {
    max_size: usize,
    max_depth: usize,
    max_string_length: usize,
    max_array_length: usize,
    max_object_keys: usize,
}

impl Default for SecureJsonParser {
    fn default() -> Self {
        Self {
            max_size: 1024 * 1024,        // 1MB total
            max_depth: 32,                // Prevent deeply nested objects
            max_string_length: 64 * 1024, // 64KB strings
            max_array_length: 10_000,     // Max array elements
            max_object_keys: 1_000,       // Max object properties
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JsonSecurityError {
    #[error("JSON too large: {size} bytes (max: {max})")]
    TooLarge { size: usize, max: usize },
    #[error("JSON too deep: {depth} levels (max: {max})")]
    TooDeep { depth: usize, max: usize },
    #[error("String too long: {length} chars (max: {max})")]
    StringTooLong { length: usize, max: usize },
    #[error("Array too large: {length} elements (max: {max})")]
    ArrayTooLarge { length: usize, max: usize },
    #[error("Object has too many keys: {count} (max: {max})")]
    TooManyKeys { count: usize, max: usize },
    #[error("JSON parsing error: {0}")]
    ParseError(#[from] serde_json::Error),
}

impl SecureJsonParser {
    /// Parse JSON from bytes with size and structure limits
    pub fn parse_from_slice(&self, data: &[u8]) -> Result<Value, JsonSecurityError> {
        // First limit: total size
        if data.len() > self.max_size {
            return Err(JsonSecurityError::TooLarge {
                size: data.len(),
                max: self.max_size,
            });
        }

        let value: Value = serde_json::from_slice(data)?;
        self.validate_structure(&value, 0)?;
        Ok(value)
    }

    /// Parse JSON from a reader with size limits
    pub fn parse_from_reader<R: Read>(&self, reader: R) -> Result<Value, JsonSecurityError> {
        let mut buffer = Vec::new();
        let bytes_read = reader
            .take(self.max_size as u64 + 1)
            .read_to_end(&mut buffer)
            .map_err(|_| JsonSecurityError::TooLarge {
                size: self.max_size + 1,
                max: self.max_size,
            })?;

        if bytes_read > self.max_size {
            return Err(JsonSecurityError::TooLarge {
                size: bytes_read,
                max: self.max_size,
            });
        }

        let value: Value = serde_json::from_slice(&buffer)?;
        self.validate_structure(&value, 0)?;
        Ok(value)
    }

    /// Recursively validate JSON structure to prevent bombs
    fn validate_structure(&self, value: &Value, depth: usize) -> Result<(), JsonSecurityError> {
        if depth > self.max_depth {
            return Err(JsonSecurityError::TooDeep {
                depth,
                max: self.max_depth,
            });
        }

        match value {
            Value::String(s) => {
                if s.len() > self.max_string_length {
                    return Err(JsonSecurityError::StringTooLong {
                        length: s.len(),
                        max: self.max_string_length,
                    });
                }
            }
            Value::Array(arr) => {
                if arr.len() > self.max_array_length {
                    return Err(JsonSecurityError::ArrayTooLarge {
                        length: arr.len(),
                        max: self.max_array_length,
                    });
                }
                for item in arr {
                    self.validate_structure(item, depth + 1)?;
                }
            }
            Value::Object(obj) => {
                if obj.len() > self.max_object_keys {
                    return Err(JsonSecurityError::TooManyKeys {
                        count: obj.len(),
                        max: self.max_object_keys,
                    });
                }
                for (key, val) in obj {
                    if key.len() > self.max_string_length {
                        return Err(JsonSecurityError::StringTooLong {
                            length: key.len(),
                            max: self.max_string_length,
                        });
                    }
                    self.validate_structure(val, depth + 1)?;
                }
            }
            _ => {} // Numbers, bools, null are safe
        }

        Ok(())
    }
}

/// Convenience function for secure JSON parsing from bytes
pub fn secure_parse_json_slice(data: &[u8]) -> Result<Value, JsonSecurityError> {
    let parser = SecureJsonParser::default();
    parser.parse_from_slice(data)
}

/// Convenience function for secure JSON parsing from reader
pub fn secure_parse_json_reader<R: Read>(reader: R) -> Result<Value, JsonSecurityError> {
    let parser = SecureJsonParser::default();
    parser.parse_from_reader(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_limit() {
        let large_json = "\"".to_string() + &"a".repeat(2 * 1024 * 1024) + "\"";
        let result = secure_parse_json_slice(large_json.as_bytes());
        assert!(matches!(result, Err(JsonSecurityError::TooLarge { .. })));
    }

    #[test]
    fn test_depth_limit() {
        let mut deep_json = String::new();
        for _ in 0..50 {
            deep_json.push_str("{\"a\":");
        }
        deep_json.push_str('1');
        for _ in 0..50 {
            deep_json.push('}');
        }

        let result = secure_parse_json_slice(deep_json.as_bytes());
        assert!(matches!(result, Err(JsonSecurityError::TooDeep { .. })));
    }

    #[test]
    fn test_string_length_limit() {
        let long_string = "a".repeat(128 * 1024);
        let json = serde_json::json!({ "test": long_string });
        let json_str = serde_json::to_string(&json).unwrap();

        let result = secure_parse_json_slice(json_str.as_bytes());
        assert!(matches!(
            result,
            Err(JsonSecurityError::StringTooLong { .. })
        ));
    }

    #[test]
    fn test_valid_json() {
        let json = r#"{"name": "test", "value": 42, "array": [1, 2, 3]}"#;
        let result = secure_parse_json_slice(json.as_bytes());
        assert!(result.is_ok());
    }
}
