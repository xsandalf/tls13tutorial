//! # TLS 1.3 client protocol implementation in Rust
//!
//! Described data structures follow the naming convention and structure of the standard specification
//!
//! [Standard](https://datatracker.ietf.org/doc/html/rfc8446)
//!
//! [Visual guide](https://tls13.xargs.org/)
pub mod alert;
pub mod display;
pub mod extensions;
pub mod handshake;
pub mod macros;
pub mod parser;
pub mod tls_record;
use crate::extensions::ByteSerializable;
use crate::parser::ByteParser;
use crate::tls_record::TLSRecord;
use log::{error, info};
use std::collections::VecDeque;
use std::io;

/// Get all TLS Records from the byte buffer.
/// Assume we get multiple TLS Records in a single response.
/// # Errors
/// Returns an error if the data is not completely parsed as TLS records
pub fn get_records(buffer: VecDeque<u8>) -> Result<Vec<TLSRecord>, io::Error> {
    let mut records = Vec::new();
    let mut parser = ByteParser::new(buffer);
    while !parser.deque.is_empty() {
        if parser.len() < 4 {
            error!("Failed to receive a valid TLS Record");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLS Record length too short"),
            ));
        }
        let len = ((parser.deque[3].clone() as u16) << 8) | (parser.deque[4].clone() as u16);
        let record_bytes = parser.get_bytes((len as usize) + 5).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid TLSRecord length: buffer overflow",
            )
        })?;
        match TLSRecord::from_bytes(&mut ByteParser::from(record_bytes)) {
            Ok(response) => {
                info!("Response TLS Record received!");
                records.push(*response);
            }
            Err(e) => {
                error!("Failed to receive a valid TLS Record: {e}");
                return Err(e);
            }
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{handshake::TLS_VERSION_COMPATIBILITY, tls_record::*};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_get_records() {
        // Positive
        let mut vc = VecDeque::new();
        vc.extend([
            0x14, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B,
        ]);
        vc.extend([
            0x14, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B,
        ]);
        let record = TLSRecord {
            record_type: ContentType::ChangeCipherSpec,
            legacy_record_version: TLS_VERSION_COMPATIBILITY,
            length: 12 as u16,
            fragment: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            ],
        };
        for rec in get_records(vc).unwrap() {
            assert_eq!(rec, record);
        }

        // Negative
        let mut vc = VecDeque::new();
        vc.extend([0x00]);
        assert!(get_records(vc).is_err());

        let mut vc = VecDeque::new();
        vc.extend([
            0x14, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A,
        ]);
        assert!(get_records(vc).is_err());

        let mut vc = VecDeque::new();
        vc.extend([
            0x14, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B,
        ]);
        vc.extend([
            0x14, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A,
        ]);
        assert!(get_records(vc).is_err());
    }
}
