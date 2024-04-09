#![allow(clippy::module_name_repetitions)]
//! Custom parser for parsing bytes from a `VecDeque<u8>`
use std::{collections::VecDeque, io::ErrorKind};

#[derive(Debug, Clone)]
pub struct ByteParser {
    pub deque: VecDeque<u8>,
}
impl ByteParser {
    #[must_use]
    pub fn new(deque: VecDeque<u8>) -> Self {
        Self { deque }
    }
    /// Consume single byte from the deque
    pub fn get_u8(&mut self) -> Option<u8> {
        self.deque.pop_front()
    }
    /// Consume 2 bytes from the deque and convert to u16
    pub fn get_u16(&mut self) -> Option<u16> {
        //Some(u16::from_be_bytes(
        //    self.deque.drain(..2).collect::<Vec<u8>>().try_into().ok()?,
        //))
        Some(u16::from_be_bytes(
            self.drain_bytes(2).ok()?.try_into().ok()?,
        ))
    }
    /// Consume 3 bytes from the deque and convert to u24 wrapped as u32
    pub fn get_u24(&mut self) -> Option<u32> {
        let mut tmp = vec![0u8]; // Need 4 bytes to convert to u32
                                 //tmp.extend(self.deque.drain(..3).collect::<Vec<u8>>());
        tmp.extend(self.drain_bytes(3).ok()?);
        Some(u32::from_be_bytes(tmp.try_into().ok()?))
    }
    /// Consume 4 bytes from the deque and convert to u32
    pub fn get_u32(&mut self) -> Option<u32> {
        //Some(u32::from_be_bytes(
        //    self.deque.drain(..4).collect::<Vec<u8>>().try_into().ok()?,
        //))
        Some(u32::from_be_bytes(
            self.drain_bytes(4).ok()?.try_into().ok()?,
        ))
    }

    /// Consume `count` bytes from the deque and convert to `Vec<u8>`
    fn drain_bytes(&mut self, count: usize) -> Result<Vec<u8>, ErrorKind> {
        if count > self.len() {
            return Err(std::io::ErrorKind::InvalidInput);
        }
        Ok(self.deque.drain(..count).collect::<Vec<u8>>())
    }

    /// Consume `count` bytes from the deque and convert to `Vec<u8>`
    pub fn get_bytes(&mut self, count: usize) -> Option<Vec<u8>> {
        // TODO bound check, will panic. Oops...
        Some(self.drain_bytes(count).ok()?)
    }
    /// Consume all bytes from the deque
    pub fn drain(&mut self) -> Vec<u8> {
        self.deque.drain(..).collect()
    }
    /// Get the length of the deque
    #[must_use]
    pub fn len(&self) -> usize {
        self.deque.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }
    /// Generate an error for insufficient data
    /// Useful when mapping above Options to Results
    #[must_use]
    pub fn insufficient_data() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Insufficient data when parsing input bytes",
        )
    }
}

/// Allow initializing Parser from a vector of bytes
impl From<Vec<u8>> for ByteParser {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            deque: VecDeque::from(bytes),
        }
    }
}
/// Allow initializing Parser from a slice of bytes
/// E.g. `let parser = Parser::from(&[0x01, 0x02, 0x03]);`
impl From<&[u8]> for ByteParser {
    fn from(bytes: &[u8]) -> Self {
        Self {
            deque: VecDeque::from(bytes.to_vec()),
        }
    }
}
