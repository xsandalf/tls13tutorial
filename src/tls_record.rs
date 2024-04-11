//! # TLS Record protocol
//! Data structures, implementations and encoding/decoding functions.
use crate::extensions::ByteSerializable;
use crate::handshake::ProtocolVersion;
use crate::parser::ByteParser;
use log::debug;
use std::io;

const RECORD_FRAGMENT_MAX_SIZE: u16 = 2u16.pow(14);
const INNER_PLAINTEXT_MAX_SIZE: u16 = 2u16.pow(14) + 8;

/// TLS Record Content Types
#[derive(Debug, Copy, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
            ) // Unreachable error
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
            ) // Unreachable error
        })?;

        // Max size for single block is 2^14 https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
        // The length MUST NOT exceed 2^14 bytes.
        //  An endpoint that receives a record that exceeds this length MUST
        //  terminate the connection with a "record_overflow" alert.
        let length = bytes.get_u16().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient bytes for TLS Record length",
            ) // Unreachable error
        })?;

        debug!("TLS Record defined length: {}", length);

        if length > RECORD_FRAGMENT_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid TLS Record: record overflow",
            ));
        }

        if bytes.len() > length as usize {
            let fragment = bytes.get_bytes(length as usize).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid TLS Record length: buffer overflow",
                ) // Unreachable error
            })?;

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
#[derive(Debug, Clone, PartialEq)]
pub struct TLSInnerPlaintext {
    pub content: Vec<u8>, // The full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1 octets.
    pub content_type: ContentType, // Inner content type of the decrypted content
    pub zeros: Vec<u8>,
}

impl ByteSerializable for TLSInnerPlaintext {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.content);
        bytes.push(self.content_type as u8);
        bytes.extend_from_slice(&self.zeros);
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        let length = bytes.len();
        debug!("TLSInnerPlaintext defined length: {}", length);

        // The length MUST NOT exceed 2^14 + 1 octets.
        // An endpoint that receives a record that exceeds this length MUST
        // terminate the connection with a "unexpected_message" alert.
        if length > INNER_PLAINTEXT_MAX_SIZE as usize {
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

        debug!("TLSInnerPlaintext padding size: {}", padding_size);

        let (content_length, is_err) = (length - padding_size).overflowing_sub(1);

        if is_err {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLSInnerPlaintext content: length overflow",
            ));
        }

        // Minus 1 byte for content_type
        let content = bytes.get_bytes(content_length).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLSInnerPlaintext content: buffer overflow",
            ) // Unreachable error
        })?;
        let content_type = match bytes.get_u8().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient bytes for TLSInnerPlaintext record type",
            ) // Unreachable error
        })? {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        };

        debug!("TLSInnerPlaintext content type: {}", content_type as u8);

        // Remove zero padding from buffer
        let zeros = bytes.get_bytes(padding_size).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLSInnerPlaintext zeros: buffer overflow",
            ) // Unreachable error
        })?;

        Ok(Box::new(TLSInnerPlaintext {
            content,
            content_type,
            zeros,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{handshake::TLS_VERSION_COMPATIBILITY, round_trip};

    #[test]
    fn test_tls_record() {
        // Positive
        round_trip!(
            TLSRecord,
            TLSRecord {
                record_type: ContentType::ChangeCipherSpec,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: 12 as u16,
                fragment: vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
                ]
            },
            &[
                0x14, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B
            ]
        );

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(TLSRecord::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            TLSRecord::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            TLSRecord::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "TLS Record length too short: 0"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00]);
        assert!(TLSRecord::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            TLSRecord::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            TLSRecord::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid TLS Record: record overflow"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x00, 0x00, 0x00, 0x02, 0x00]);
        assert!(TLSRecord::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            TLSRecord::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            TLSRecord::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "TLS Record: length and fragment size mismatch"
        ));
    }

    #[test]
    fn test_tls_inner_plaintext() {
        // Positive
        round_trip!(
            TLSInnerPlaintext,
            TLSInnerPlaintext {
                content: vec![0x03, 0x04, 0x02, 0x01],
                content_type: ContentType::ApplicationData,
                zeros: vec![0x00, 0x00, 0x00, 0x00]
            },
            &[0x03, 0x04, 0x02, 0x01, 0x17, 0x00, 0x00, 0x00, 0x00]
        );

        // Negative
        let bytes = ByteParser::from([1u8; (INNER_PLAINTEXT_MAX_SIZE + 1) as usize].to_vec());
        assert!(TLSInnerPlaintext::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            TLSInnerPlaintext::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            TLSInnerPlaintext::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid TLSInnerPlaintext: record overflow"
        ));

        let bytes = ByteParser::from(vec![]);
        assert!(TLSInnerPlaintext::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            TLSInnerPlaintext::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            TLSInnerPlaintext::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "TLSInnerPlaintext content: length overflow"
        ));
    }
}
