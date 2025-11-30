//! # Utils

/// Reader for parsing binary data
#[derive(Debug)]
pub struct MyReader {
    /// Data
    data: Vec<u8>,
    /// Position
    pos: usize,
}

impl MyReader {
    /// Create a new reader
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            pos: 0,
        }
    }

    /// Get the length of the data
    pub(crate) const fn len(&self) -> usize {
        self.data.len()
    }

    /// Get the current position
    pub(crate) const fn get_pos(&self) -> usize {
        self.pos
    }

    /// Get the data as a vector
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Get the data as a slice
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn get_to(&mut self, len: usize) -> Result<&[u8], String> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| format!("Error: position overflow: {} + {}", self.pos, len))?;

        match self.data.get(self.pos..end) {
            Some(data) => {
                self.pos = end; // Only update position on success
                Ok(data)
            }
            None => Err(format!(
                "Error: out of bounds: {}..{} (len: {})",
                self.pos,
                end,
                self.data.len()
            )),
        }
    }

    /// Get the data as a slice
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn as_slice(&mut self, end: usize) -> Result<Self, String> {
        Ok(Self {
            data: self.get_to(end)?.to_vec(),
            pos: 0,
        })
    }

    /// Read a u32 as size
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_size(&mut self) -> Result<usize, String> {
        let temp = self.read_u32()?;
        Ok(temp as usize)
    }

    /// Read a u16
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_u16(&mut self) -> Result<u16, String> {
        let buf = match self.data.get(self.pos..self.pos + 2) {
            Some(buf) => {
                let mut buffer = [0; 2];
                buffer.copy_from_slice(buf);
                buffer
            }
            None => {
                return Err(format!(
                    "Error: out of bounds reading u16 between {} and {}",
                    self.pos,
                    self.pos + 2
                ));
            }
        };
        self.pos += 2;
        Ok(u16::from_le_bytes([buf[0], buf[1]]))
    }

    /// Read a u32
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_u32(&mut self) -> Result<u32, String> {
        let buf = match self.data.get(self.pos..self.pos + 4) {
            Some(buf) => {
                let mut buffer = [0; 4];
                buffer.copy_from_slice(buf);
                buffer
            }
            None => {
                return Err(format!(
                    "Error: out of bounds reading u32 between {} and {}",
                    self.pos,
                    self.pos + 4
                ));
            }
        };
        self.pos += 4;
        Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }

    /// Read a u64
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_u64(&mut self) -> Result<u64, String> {
        let buf = match self.data.get(self.pos..self.pos + 8) {
            Some(buf) => {
                let mut buffer = [0; 8];
                buffer.copy_from_slice(buf);
                buffer
            }
            None => {
                return Err(format!(
                    "Error: out of bounds reading u64 between {} and {}",
                    self.pos,
                    self.pos + 8
                ));
            }
        };
        self.pos += 8;
        Ok(u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]))
    }

    /// Read a u64 as size
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_size_u64(&mut self) -> Result<usize, String> {
        let temp = self.read_u64()?;
        Ok(temp as usize)
    }
}

/// Create a fixed buffer of 8 bytes
pub(crate) const fn create_fixed_buffer_8(buf: &[u8]) -> [u8; 8] {
    let mut buffer = [0; 8];
    buffer.copy_from_slice(buf);
    buffer
}
