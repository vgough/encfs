use anyhow::{Context, Result};
use std::collections::HashMap;

/// A configuration variable holder for the legacy EncFS binary config format.
///
/// EncFS binary configuration (v5 and older) consists of a list of variables.
/// Each variable is encoded as a length + value:
/// - [Length of Key] [Key String]
/// - [Length of Value Content] [Value Content]
///
/// Integers are encoded using a variable-length quantity (VLQ) encoding.
#[derive(Clone)]
pub struct ConfigVar {
    buffer: Vec<u8>,
    offset: usize,
}

impl ConfigVar {
    pub fn new(buffer: Vec<u8>) -> Self {
        Self { buffer, offset: 0 }
    }

    pub fn at(&self) -> usize {
        self.offset
    }

    /// Reads a variable-length encoded integer (VLQ) from the buffer.
    pub fn read_int(&mut self) -> Result<i32> {
        let mut value = 0;

        if self.offset >= self.buffer.len() {
            return Err(anyhow::anyhow!("End of buffer"));
        }

        loop {
            if self.offset >= self.buffer.len() {
                break;
            }
            let tmp = self.buffer[self.offset];
            self.offset += 1;
            let high_bit_set = (tmp & 0x80) != 0;
            value = (value << 7) | (tmp & 0x7f) as i32;

            if !high_bit_set {
                break;
            }
        }

        Ok(value)
    }

    pub fn read_int_default(&mut self, default_value: i32) -> i32 {
        if self.offset >= self.buffer.len() {
            return default_value;
        }
        self.read_int().unwrap_or(default_value)
    }

    pub fn read_bool(&mut self, default_value: bool) -> bool {
        let val = self.read_int_default(if default_value { 1 } else { 0 });
        val != 0
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_int().context("Failed to read string length")?;
        if len < 0 {
            return Err(anyhow::anyhow!("Invalid string length: {}", len));
        }
        let len = len as usize;

        if self.offset + len > self.buffer.len() {
            return Err(anyhow::anyhow!("String length out of bounds"));
        }

        let bytes = &self.buffer[self.offset..self.offset + len];
        self.offset += len;
        Ok(bytes.to_vec())
    }

    pub fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        // Note: The C++ code doesn't strictly validate UTF-8, but String requires it.
        // EncFS configs should be ASCII/UTF-8.
        String::from_utf8(bytes).context("Invalid UTF-8 string")
    }

    pub fn read_u8_vector(&mut self) -> Result<Vec<u8>> {
        self.read_bytes()
    }
}

/// Helper to read a full binary configuration structure.
///
/// The structure is:
/// [Number of Entries (int)]
/// For each entry:
///   [Key String (as length-prefixed string)]
///   [Value Blob (as length-prefixed byte array)]
///
/// The Value Blob is normally parsed by creating another `ConfigVar` from it.
pub struct ConfigReader {
    pub vars: HashMap<String, ConfigVar>,
}

impl ConfigReader {
    pub fn new(data: &[u8]) -> Result<Self> {
        let mut reader = ConfigVar::new(data.to_vec());
        reader.offset = 0; // Ensure start

        let num_entries = reader
            .read_int()
            .context("Failed to read number of entries")?;

        let mut vars = HashMap::new();

        for _ in 0..num_entries {
            let key = reader.read_string().context("Failed to read key")?;
            // The value is also a length-prefixed blob (ConfigVar serialization)
            // In C++: in >> key >> value;
            // where value is read as a string (length + bytes) then wrapped in a ConfigVar.
            let value_blob = reader.read_bytes().context("Failed to read value blob")?;

            vars.insert(key, ConfigVar::new(value_blob));
        }

        Ok(Self { vars })
    }

    pub fn get(&self, key: &str) -> Option<ConfigVar> {
        self.vars.get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_int() {
        // 0x7f -> 127
        let mut cv = ConfigVar::new(vec![0x7f]);
        assert_eq!(cv.read_int().unwrap(), 127);

        // 0x81, 0x00 -> 128
        // 1000,0001 0000,0000
        // high bit set, val = (0 << 7) | 1 = 1.
        // next byte 00. val = (1 << 7) | 0 = 128.
        let mut cv = ConfigVar::new(vec![0x81, 0x00]);
        assert_eq!(cv.read_int().unwrap(), 128);
    }

    #[test]
    fn test_read_string() {
        // len=3, "foo"
        let mut data = vec![3];
        data.extend_from_slice(b"foo");
        let mut cv = ConfigVar::new(data);
        assert_eq!(cv.read_string().unwrap(), "foo");
    }

    #[test]
    fn test_config_reader() {
        // V5 Config mock
        // ConfigReader format: numEntries, (key, value)*
        // ConfigVar writeString writes: length, bytes

        // Let's create a serialized buffer
        let mut data = Vec::new();
        // num entries = 1 (encoded as int)
        data.push(1);

        // Entry Key = "test"
        // key length = 4
        data.push(4);
        data.extend_from_slice(b"test");

        // Entry Value = "val"
        // value length = 3
        data.push(3);
        data.extend_from_slice(b"val");

        let reader = ConfigReader::new(&data).unwrap();
        let val = reader.get("test").unwrap();
        // The inner buffer of val should be "val"
        assert_eq!(val.buffer, b"val");
    }
}
