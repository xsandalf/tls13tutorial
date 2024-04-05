//! # TLS Record protocol
//! Data structures, implementations and encoding/decoding functions.
use crate::extensions::ByteSerializable;
use crate::handshake::ProtocolVersion;
use crate::parser::ByteParser;
use log::debug;
use std::io;

const RECORD_FRAGMENT_MAX_SIZE: u16 = 2u16.pow(14);
const INNERPLAINTEXT_MAX_SIZE: u16 = 2u16.pow(14) + 8;

/// TLS Record Content Types
#[derive(Debug, Copy, Clone)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// [TLS Record Layer](https://datatracker.ietf.org/doc/html/rfc8446#section-5.1)
/// Application Data is always encrypted, in that case the record represents `TLSCiphertext`
/// Message boundaries are handled differently depending on the underlying `ContentType`.
#[derive(Debug, Clone)]
pub struct TLSRecord {
    pub record_type: ContentType,
    pub legacy_record_version: ProtocolVersion, // 2 bytes to represent
    // always 0x0303 for TLS 1.3, except for the first ClientHello where it can be 0x0301
    pub length: u16,       // length defined as 2 bytes
    pub fragment: Vec<u8>, // fragment of size 'length' either plaintext data or ciphertext
}

impl ByteSerializable for TLSRecord {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.push(self.record_type as u8);
        bytes.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.fragment);
        Some(bytes)
    }
    /// Parse the bytes into a `TLSPlaintext` struct
    /// Returns `Result` object with the parsed `TLSPlaintext` object and the remaining bytes
    /// `Box` structure is used to wrap the data of the struct into a heap-allocated memory
    /// In stack, only the pointer to the heap memory is stored to make compiler known the size
    /// of the return type in compile-time.
    /// NOTE The implementation might not be secure...
    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        if bytes.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLS Record length too short: {}", bytes.len()),
            ));
        }
        let record_type = match bytes.get_u8().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient bytes for TLS Record record type",
            )
        })? {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        };
        let legacy_record_version = bytes.get_u16().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient bytes for TLS Record legacy record version",
            )
        })?;

        // Max size for single block is 2^14 https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
        // The length MUST NOT exceed 2^14 bytes.
        //  An endpoint that receives a record that exceeds this length MUST
        //  terminate the connection with a "record_overflow" alert.
        let length = bytes.get_u16().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient bytes for TLS Record length",
            )
        })?;
        debug!("TLS Record defined length: {}", length);
        if length > RECORD_FRAGMENT_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid TLS Record: record overflow",
            ));
        }
        if bytes.len() > length as usize {
            let fragment = bytes.get_bytes(length as usize);
            Ok(Box::from(TLSRecord {
                record_type,
                legacy_record_version,
                length,
                fragment,
            }))
        } else {
            if bytes.len() != length as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS Record: length and fragment size mismatch",
                ));
            }
            Ok(Box::from(TLSRecord {
                record_type,
                legacy_record_version,
                length,
                fragment: bytes.drain(),
            }))
        }
    }
}

/// Data structure for the decrypted content of a TLS Record.
#[derive(Debug, Clone)]
pub struct TLSInnerPlaintext {
    pub content: Vec<u8>, // The full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1 octets.
    pub content_type: ContentType, // Inner content type of the decrypted content
    pub zeros: Vec<u8>,
}
impl ByteSerializable for TLSInnerPlaintext {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        // TODO: Untested. todo!("Implement TLSInnerPlaintext as_bytes");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.content);
        bytes.push(self.content_type as u8);
        bytes.extend_from_slice(&self.zeros);
        Some(bytes)
    }
    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // TODO: Untested. todo!("Implement TLSInnerPlaintext from_bytes")
        let length = bytes.len();
        debug!("TLSInnerPlaintext defined length: {}", length);
        // The length MUST NOT exceed 2^14 + 1 octets.
        // An endpoint that receives a record that exceeds this length MUST
        // terminate the connection with a "unexpected_message" alert.
        if length > INNERPLAINTEXT_MAX_SIZE as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid TLSInnerPlaintext: record overflow",
            ));
        }

        // NOTE: Feels stupid again
        // Zeroes are padded to the end so we have to loop backwards to find how many there are
        let mut padding_size = 0;
        for byte in bytes.deque.iter().rev() {
            if *byte != 0 {
                break;
            }
            padding_size += 1;
        }
        let content = bytes.get_bytes(padding_size);
        let content_type = match bytes.get_u8().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient bytes for TLSInnerPlaintext record type",
            )
        })? {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        };

        // NOTE: Risky
        // Rest of the bytes in the buffer should be zero padding bytes
        let zeros = bytes.drain();
        Ok(Box::new(TLSInnerPlaintext {
            content,
            content_type,
            zeros,
        }))
    }
}
