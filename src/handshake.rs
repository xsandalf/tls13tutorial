//! This module contains the structures and implementations for the handshake messages.
#![allow(clippy::module_name_repetitions)]
use crate::extensions::{ByteSerializable, Extension, ExtensionOrigin, SignatureScheme};
use crate::handshake::cipher_suites::CipherSuite;
use crate::parser::ByteParser;
use log::debug;
use std::collections::VecDeque;

pub type ProtocolVersion = u16;
pub type Random = [u8; 32];

pub const TLS_VERSION_COMPATIBILITY: ProtocolVersion = 0x0303;
pub const TLS_VERSION_1_3: ProtocolVersion = 0x0304;

/// ## Cipher Suites
/// TLS 1.3 supports only five different cipher suites
/// Our client primarily supports ChaCha20-Poly1305 with SHA-256
/// See more [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4)
pub mod cipher_suites {
    #[derive(Debug, Copy, Clone, PartialEq)]
    pub struct CipherSuite([u8; 2]);
    impl AsRef<[u8]> for CipherSuite {
        #[must_use]
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; 2]> for CipherSuite {
        fn from(slice: [u8; 2]) -> Self {
            CipherSuite(slice)
        }
    }

    impl From<Vec<u8>> for CipherSuite {
        fn from(slice: Vec<u8>) -> Self {
            let mut arr = [0u8; 2];
            arr.copy_from_slice(&slice);
            CipherSuite(arr)
        }
    }

    pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite([0x13, 0x01]);
    pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite([0x13, 0x02]);
    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite([0x13, 0x03]);
    pub const TLS_AES_128_CCM_SHA256: CipherSuite = CipherSuite([0x13, 0x04]);
    pub const TLS_AES_128_CCM_8_SHA256: CipherSuite = CipherSuite([0x13, 0x05]);

    /// Pretty print the cipher suite
    impl std::fmt::Display for CipherSuite {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                [0x13, 0x01] => write!(f, "[0x13, 0x01] TLS_AES_128_GCM_SHA256"),
                [0x13, 0x02] => write!(f, "[0x13, 0x02] TLS_AES_256_GCM_SHA384"),
                [0x13, 0x03] => write!(f, "[0x13, 0x03] TLS_CHACHA20_POLY1305_SHA256"),
                [0x13, 0x04] => write!(f, "[0x13, 0x04] TLS_AES_128_CCM_SHA256"),
                [0x13, 0x05] => write!(f, "[0x13, 0x05] TLS_AES_128_CCM_8_SHA256"),
                e => write!(f, "Unknown Cipher Suite: {e:?}"),
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EndOfEarlyData,
    EncryptedExtensions(EncryptedExtensions),
    CertificateRequest,
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    NewSessionTicket,
    KeyUpdate,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Handshake {
    pub msg_type: HandshakeType,
    pub length: u32, // length of the data can be 0..2^24-1 (3 bytes to present)
    pub message: HandshakeMessage,
}

impl ByteSerializable for Handshake {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.push(self.msg_type as u8);

        if self.length <= 0x00FF_FFFF {
            // convert u32 to 3 bytes
            bytes.extend_from_slice(&self.length.to_be_bytes()[1..]);
        } else {
            return None;
        }

        match &self.message {
            HandshakeMessage::ClientHello(client_hello) => {
                bytes.extend_from_slice(&client_hello.as_bytes()?);
            }
            HandshakeMessage::ServerHello(server_hello) => {
                bytes.extend_from_slice(&server_hello.as_bytes()?);
            }
            HandshakeMessage::EncryptedExtensions(encrypted_extensions) => {
                bytes.extend_from_slice(&encrypted_extensions.as_bytes()?);
            }
            HandshakeMessage::Certificate(certificate) => {
                bytes.extend_from_slice(&certificate.as_bytes()?);
            }
            HandshakeMessage::CertificateVerify(certificate_verify) => {
                bytes.extend_from_slice(&certificate_verify.as_bytes()?);
            }
            HandshakeMessage::Finished(finished) => {
                bytes.extend_from_slice(&finished.as_bytes()?);
            }
            _ => {}
        }

        Some(bytes)
    }

    /// Parse the bytes into a `Handshake` struct.
    /// We only support `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify` and `Finished` messages.
    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        let hs_type = match bytes.get_u8() {
            Some(1) => HandshakeType::ClientHello,
            Some(2) => HandshakeType::ServerHello,
            Some(8) => HandshakeType::EncryptedExtensions,
            Some(11) => HandshakeType::Certificate,
            Some(15) => HandshakeType::CertificateVerify,
            Some(20) => HandshakeType::Finished,
            e => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid or unimplemented handshake type: {e:?}"),
                ))
            }
        };

        let msg_length = bytes.get_u24().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid handshake message length",
            )
        })?;

        debug!("Handshake message length: {:?}", msg_length);
        let mut hs_bytes = ByteParser::new(VecDeque::from(
            bytes.get_bytes(msg_length as usize).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid handshake message length: buffer overflow",
                )
            })?,
        ));
        let mut checksum = Vec::new();

        #[cfg(debug_assertions)]
        {
            checksum.push(hs_type.clone() as u8);
            checksum.extend_from_slice(&msg_length.clone().to_be_bytes()[1..]);
            checksum.extend(hs_bytes.deque.clone().iter());
        }

        let hs_message = match hs_type {
            HandshakeType::ClientHello => {
                let client_hello = ClientHello::from_bytes(&mut hs_bytes)?;
                HandshakeMessage::ClientHello(*client_hello)
            }
            HandshakeType::ServerHello => {
                let server_hello = ServerHello::from_bytes(&mut hs_bytes)?;
                HandshakeMessage::ServerHello(*server_hello)
            }
            HandshakeType::EncryptedExtensions => {
                let encrypted_extensions = EncryptedExtensions::from_bytes(&mut hs_bytes)?;
                HandshakeMessage::EncryptedExtensions(*encrypted_extensions)
            }
            HandshakeType::Certificate => {
                let certificate = Certificate::from_bytes(&mut hs_bytes)?;
                HandshakeMessage::Certificate(*certificate)
            }
            HandshakeType::CertificateVerify => {
                let certificate_verify = CertificateVerify::from_bytes(&mut hs_bytes)?;
                HandshakeMessage::CertificateVerify(*certificate_verify)
            }
            HandshakeType::Finished => {
                let finished = Finished::from_bytes(&mut hs_bytes)?;
                HandshakeMessage::Finished(*finished)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid handshake message type",
                ))
            }
        };

        let handshake = Handshake {
            msg_type: hs_type,
            length: msg_length,
            message: hs_message,
        };

        // Helper to identify that decoded bytes are encoded back to the same bytes
        #[cfg(debug_assertions)]
        {
            assert_eq!(checksum, handshake.as_bytes().unwrap());
        }
        Ok(Box::from(handshake))
    }
}

/// `Finished` message is the final message in the Authentication Block.
#[derive(Debug, Clone, PartialEq)]
pub struct Finished {
    // NOTE: Length is not actually included in the bytes. Length is based on the HMAC used for the handshake
    // We currently support only 32 byte HMAC
    pub verify_data: Vec<u8>, // length can be presented with single byte
}

impl ByteSerializable for Finished {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(self.verify_data.iter());
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        let checksum;

        #[cfg(debug_assertions)]
        {
            checksum = bytes.deque.clone();
        }

        // TODO: Check HMAC in use and choose length based on it
        let length = 32;
        let verify_data = bytes.get_bytes(length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid Finished verify_data length: buffer overflow",
            )
        })?;
        let finished = Finished { verify_data };

        // Helper to identify that decoded bytes are encoded back to the same bytes
        #[cfg(debug_assertions)]
        {
            assert_eq!(checksum, finished.as_bytes().unwrap());
        }

        Ok(Box::new(finished))
    }
}

/// [`ClientHello`](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2)
/// TLS 1.3 `ClientHello`s are identified as having
///       a `legacy_version` of 0x0303 and a `supported_versions` extension
///       present with 0x0304 as the highest version indicated therein.
///       (See Appendix D for details about backward compatibility.)
#[derive(Debug, Clone, PartialEq)]
pub struct ClientHello {
    pub legacy_version: ProtocolVersion,     // 2 bytes to represent
    pub random: Random,                      // Static 32 bytes, no length prefix
    pub legacy_session_id: Vec<u8>,          // length of the data can be 0..32 (1 byte to present)
    pub cipher_suites: Vec<CipherSuite>,     // length of the data can be 2..2^16-2 (2 bytes)
    pub legacy_compression_methods: Vec<u8>, // length of the data can be 1..2^8-1 (1 byte)
    pub extensions: Vec<Extension>, // length of the data can be 8..2^16-1 (2 bytes to present)
}

/// Implements inner encoders and decoders for `ClientHello` struct.
/// For clarity, each field is encoded separately to bytes.
impl ClientHello {
    fn version_bytes(&self) -> Vec<u8> {
        self.legacy_version.to_be_bytes().to_vec()
    }

    fn random_bytes(&self) -> &[u8] {
        self.random.as_ref()
    }

    fn session_id_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        bytes.push(self.legacy_session_id.len() as u8);
        bytes.extend_from_slice(self.legacy_session_id.as_slice());
        bytes
    }

    fn cipher_suites_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let len_ciphers: usize = self.cipher_suites.iter().fold(0, |acc, _x| acc + 2);
        #[allow(clippy::cast_possible_truncation)]
        bytes.extend_from_slice((len_ciphers as u16).to_be_bytes().as_ref());
        for cipher_suite in &self.cipher_suites {
            bytes.extend_from_slice(cipher_suite.as_ref());
        }
        bytes
    }

    #[allow(clippy::unused_self)]
    fn compression_methods_bytes(&self) -> Vec<u8> {
        vec![0x01, 0x00] // TLS 1.3 does not support compression
    }

    fn extensions_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut ext_bytes = Vec::new();
        for extension in &self.extensions {
            ext_bytes.extend(extension.as_bytes()?);
        }
        // 2 byte length determinant for `extensions`
        bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
        bytes.extend(ext_bytes);
        Some(bytes)
    }
}

impl ByteSerializable for ClientHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(&self.version_bytes());
        bytes.extend_from_slice(self.random_bytes());
        bytes.extend(&self.session_id_bytes());
        bytes.extend(&self.cipher_suites_bytes());
        bytes.extend(&self.compression_methods_bytes());
        bytes.extend(&self.extensions_bytes()?);
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // TODO: Untest. todo!("Implement ClientHello::from_bytes")
        #[allow(unused)]
        let checksum: VecDeque<u8>;

        #[cfg(debug_assertions)]
        {
            checksum = bytes.deque.clone();
        }

        let legacy_version = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ClientHello legacy version",
            )
        })?;

        let random: Random = bytes
            .get_bytes(32)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ClientHello random length: buffer overflow",
                )
            })?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ClientHello random",
                )
            })?;

        let session_id_length = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ClientHello session id length",
            )
        })?;

        let session_id = bytes.get_bytes(session_id_length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ClientHello session_id length: buffer overflow",
            )
        })?;

        let cipher_suites_length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ClientHello cipher_suites length",
            )
        })?;

        let mut ciph_suites = Vec::new();
        let cipher_suite_bytes =
            bytes
                .get_bytes(cipher_suites_length as usize)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ClientHello cipher_suites length: buffer overflow",
                    )
                })?;

        let mut cs_parser = ByteParser::new(VecDeque::from(cipher_suite_bytes));

        while !cs_parser.deque.is_empty() {
            let cs = CipherSuite::from(cs_parser.get_bytes(2).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ClientHello cipher suite",
                )
            })?);
            ciph_suites.push(cs);
        }

        let compression_methods_length = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ClientHello compression methods length",
            )
        })?;

        let compression_methods = bytes
            .get_bytes(compression_methods_length as usize)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ClientHello compression methods length: buffer overflow",
                )
            })?;

        let extension_length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ClientHello extension length",
            )
        })?;

        let mut extensions = Vec::new();
        let extension_bytes = bytes.get_bytes(extension_length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ClientHello extensions length: buffer overflow",
            )
        })?;

        let mut ext_parser = ByteParser::new(VecDeque::from(extension_bytes));

        while !ext_parser.deque.is_empty() {
            let extension = Extension::from_bytes(&mut ext_parser, ExtensionOrigin::Client)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ClientHello Extension",
                    )
                })?;
            extensions.push(*extension);
        }

        let client_hello = Box::from(ClientHello {
            legacy_version,
            random,
            legacy_session_id: session_id,
            cipher_suites: ciph_suites,
            legacy_compression_methods: compression_methods,
            extensions,
        });

        // Helper to identify that decoded bytes are encoded back to the same bytes
        #[cfg(debug_assertions)]
        {
            assert_eq!(checksum, client_hello.as_bytes().unwrap());
        }

        Ok(client_hello)
    }
}

/// `ServerHello` message
#[derive(Debug, Clone, PartialEq)]
pub struct ServerHello {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub legacy_session_id_echo: Vec<u8>, // length of the data can be 0..32
    pub cipher_suite: CipherSuite,
    pub legacy_compression_method: u8,
    pub extensions: Vec<Extension>, // length of the data can be 6..2^16-1 (2 bytes to present)
}

impl ByteSerializable for ServerHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(self.legacy_version.to_be_bytes().iter());
        bytes.extend(self.random.iter());
        bytes.push(u8::try_from(self.legacy_session_id_echo.len()).ok()?);
        bytes.extend(self.legacy_session_id_echo.iter());
        bytes.extend(self.cipher_suite.as_ref());
        bytes.push(self.legacy_compression_method);

        let mut ext_bytes = Vec::new();

        for extension in &self.extensions {
            ext_bytes.extend(extension.as_bytes()?);
        }

        bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
        bytes.extend(ext_bytes);

        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        #[allow(unused)]
        let checksum: VecDeque<u8>;

        #[cfg(debug_assertions)]
        {
            checksum = bytes.deque.clone();
        }

        let legacy_version = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello legacy version",
            )
        })?;

        let random: Random = bytes
            .get_bytes(32)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ServerHello random length: buffer overflow",
                )
            })?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ServerHello random",
                )
            })?;

        let session_id_length = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello session id length",
            )
        })?;

        let session_id = bytes.get_bytes(session_id_length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello session_id length: buffer overflow",
            )
        })?;

        let cipher_suite: CipherSuite = bytes
            .get_bytes(2)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ServerHello cipher_suite length: buffer overflow",
                )
            })?
            .into();

        let compression_method = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello compression method",
            )
        })?;

        let extension_length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello extension length",
            )
        })?;

        let mut extensions = Vec::new();
        let extension_bytes = bytes.get_bytes(extension_length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello extensions length: buffer overflow",
            )
        })?;

        let mut ext_parser = ByteParser::new(VecDeque::from(extension_bytes));

        while !ext_parser.deque.is_empty() {
            let extension = Extension::from_bytes(&mut ext_parser, ExtensionOrigin::Server)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ServerHello Extension",
                    )
                })?;
            extensions.push(*extension);
        }

        let server_hello = Box::from(ServerHello {
            legacy_version,
            random,
            legacy_session_id_echo: session_id,
            cipher_suite,
            legacy_compression_method: compression_method,
            extensions,
        });

        // Helper to identify that decoded bytes are encoded back to the same bytes
        #[cfg(debug_assertions)]
        {
            assert_eq!(checksum, server_hello.as_bytes().unwrap());
        }

        Ok(server_hello)
    }
}

/// `CertificateType` which is presented with 1-byte enum values
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CertificateType {
    X509 = 0,
    RawPublicKey = 2,
}

/// A single certificate and set of extensions as defined in Section 4.2.
/// TODO: Implement ByteSerializable
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateEntry {
    pub certificate_type: CertificateType, // NOTE: This is not included in the messages. Do not encode/decode
    pub certificate_data: Vec<u8>, // length of the data can be 1..2^24-1 (3 bytes to present)
    pub extensions: Vec<Extension>, // length of the data can be 0..2^16-1 (2 bytes to present)
}

/// [`Certificate` message](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2)
///  This message conveys the endpoint's certificate chain to the peer.
#[derive(Debug, Clone, PartialEq)]
pub struct Certificate {
    pub certificate_request_context: Vec<u8>, // length of the data can be 0..255 (1 byte to present)
    pub certificate_list: Vec<CertificateEntry>, // length of the data can be 0..2^24-1 (3 bytes to present)
}

impl ByteSerializable for Certificate {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        // TODO: Refactor, this is a mess
        let mut bytes = Vec::new();

        // 1 byte length determinant for the certificate_request_context
        bytes.push(u8::try_from(self.certificate_request_context.len()).ok()?);
        bytes.extend(self.certificate_request_context.iter());

        let mut ce_bytes = Vec::new();

        for cert_entry in &self.certificate_list {
            // 3 byte length determinant for the certificate_data
            ce_bytes.extend_from_slice(
                u32::try_from(cert_entry.certificate_data.len())
                    .ok()?
                    .to_be_bytes()[1..]
                    .as_ref(),
            );

            ce_bytes.extend_from_slice(&cert_entry.certificate_data);

            // This could be replaced with EncryptedExtensions::as_bytes(), since it only encodes the Vec<Extension>
            let mut ext_bytes = Vec::new();
            for extension in &cert_entry.extensions {
                ext_bytes.extend(extension.as_bytes()?);
            }

            ce_bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
            ce_bytes.extend(ext_bytes);
        }

        // 3 byte length determinant for the certificate_list
        bytes.extend_from_slice(u32::try_from(ce_bytes.len()).ok()?.to_be_bytes()[1..].as_ref());
        bytes.extend(ce_bytes);

        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        let checksum;

        #[cfg(debug_assertions)]
        {
            checksum = bytes.deque.clone();
        }

        // TODO: Refactor, this is a mess
        // 1 byte length determinant for the certificate_request_context
        let crc_length = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid certificate request context length",
            )
        })?;

        let crc = bytes.get_bytes(crc_length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid certificate_request_context length: buffer overflow",
            )
        })?;

        let list_length = bytes.get_u24().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid certificate list length",
            )
        })?;

        // NOTE: Stupid loop time
        let mut i = 0;
        let mut cert_entries = Vec::new();

        while i < list_length {
            // 3 byte length determinant for the certificate_data
            let cert_data_length = bytes.get_u24().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid CertificateEntry certification data length",
                )
            })?;

            let cert_data = bytes.get_bytes(cert_data_length as usize).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid certificate_data length: buffer overflow",
                )
            })?;

            // This could be replaced with EncryptedExtensions::from_bytes(), since it only decodes the Vec<Extension>
            // 2 byte length determinant for the extensions
            let extension_length = bytes.get_u16().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid CertificateEntry extension length",
                )
            })?;

            let mut extensions = Vec::new();
            let extension_bytes = bytes.get_bytes(extension_length as usize).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid Certificate extensions length: buffer overflow",
                )
            })?;
            let mut ext_parser = ByteParser::new(VecDeque::from(extension_bytes));

            while !ext_parser.deque.is_empty() {
                let extension = Extension::from_bytes(&mut ext_parser, ExtensionOrigin::Server)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid Certificate Extension",
                        )
                    })?;
                extensions.push(*extension);
            }

            cert_entries.push(CertificateEntry {
                // NOTE: No idea how this is determined, probably SupportedGroup or SignatureAlgorithm
                // Leaning towards SignatureAlgorithm
                // TODO: Figure this out and implement
                certificate_type: CertificateType::X509,
                certificate_data: cert_data,
                extensions,
            });

            // NOTE: Dumb
            // 1 for certificate_type, 3 for certificate_data length, 2 for extensions length
            i += 1 + 3 + cert_data_length + 2 + (extension_length as u32);
        }

        let certificate = Certificate {
            certificate_request_context: crc,
            certificate_list: cert_entries,
        };

        // Helper to identify that decoded bytes are encoded back to the same bytes
        #[cfg(debug_assertions)]
        {
            assert_eq!(checksum, certificate.as_bytes().unwrap());
        }

        Ok(Box::new(certificate))
    }
}

/// `EncryptedExtensions` message
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>, // length of the data can be 0..2^16-1 (2 bytes to present)
}

impl ByteSerializable for EncryptedExtensions {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut ext_bytes = Vec::new();

        for extension in &self.extensions {
            ext_bytes.extend(extension.as_bytes()?);
        }

        bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
        bytes.extend(ext_bytes);

        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        let checksum;

        #[cfg(debug_assertions)]
        {
            checksum = bytes.deque.clone();
        }

        // 2 byte length determinant for the extensions
        let extension_length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid EncryptedExtensions extension length",
            )
        })?;

        let mut extensions = Vec::new();
        let extension_bytes = bytes.get_bytes(extension_length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid EncryptedExtensions extensions length: buffer overflow",
            )
        })?;

        let mut ext_parser = ByteParser::new(VecDeque::from(extension_bytes));

        while !ext_parser.deque.is_empty() {
            let extension = Extension::from_bytes(&mut ext_parser, ExtensionOrigin::Server)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid EncryptedExtensions Extension",
                    )
                })?;
            extensions.push(*extension);
        }

        let encrypted_extensions = EncryptedExtensions { extensions };

        // Helper to identify that decoded bytes are encoded back to the same bytes
        #[cfg(debug_assertions)]
        {
            assert_eq!(checksum, encrypted_extensions.as_bytes().unwrap());
        }

        Ok(Box::new(encrypted_extensions))
    }
}

/// `CertificateVerify` message
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateVerify {
    pub algorithm: SignatureScheme,
    pub signature: Vec<u8>, // length of the data can be 0..2^16-1 (2 bytes to present)
}

impl ByteSerializable for CertificateVerify {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.algorithm.as_bytes()?);

        // 2 byte length determinant for the signature
        bytes.extend(u16::try_from(self.signature.len()).ok()?.to_be_bytes());
        bytes.extend(self.signature.iter());
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        let checksum;

        #[cfg(debug_assertions)]
        {
            checksum = bytes.deque.clone();
        }

        let signature_scheme = *SignatureScheme::from_bytes(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid CertificateVerify SignatureScheme",
            )
        })?;

        // 2 byte length determinant for the signature
        let length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid CertificateVerify signature length",
            )
        })?;

        let signature = bytes.get_bytes(length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid CertificateVerifty signature length: buffer overflow",
            )
        })?;

        let certificate_verify = CertificateVerify {
            algorithm: signature_scheme,
            signature,
        };

        // Helper to identify that decoded bytes are encoded back to the same bytes
        #[cfg(debug_assertions)]
        {
            assert_eq!(checksum, certificate_verify.as_bytes().unwrap());
        }

        Ok(Box::new(certificate_verify))
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    // NOTE: ExtensionData tests not included due to incomplete implementation of from_bytes()
    use super::*;
    use crate::{display::to_hex, extensions::*, round_trip};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_finished() {
        // Positive
        round_trip!(
            Finished,
            Finished {
                verify_data: vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                ]
            },
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F,
            ]
        );

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(Finished::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Finished::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Finished::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid Finished verify_data length: buffer overflow"
        ));
    }

    #[test]
    fn test_handshake_finished() {
        let handshake = Handshake {
            msg_type: HandshakeType::Finished,
            length: 32 as u32,
            message: HandshakeMessage::Finished(Finished {
                verify_data: vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                ],
            }),
        };
        let bytes = handshake.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x14, 0x00, 0x00, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
            ]
        );
        let hs = Handshake::from_bytes(&mut ByteParser::from(bytes)).unwrap();
        assert_eq!(*hs, handshake);
    }

    #[test]
    fn test_client_hello() {
        // Positive
        round_trip!(
            ClientHello,
            ClientHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                ],
                legacy_session_id: vec![0x01, 0x0F],
                cipher_suites: vec![
                    cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
                    cipher_suites::TLS_AES_128_CCM_SHA256
                ],
                legacy_compression_methods: vec![0x00],
                extensions: vec![
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::Cookie,
                        extension_data: ExtensionData::Cookie(Cookie {
                            cookie: vec![0x03, 0x0F, 0x04, 0x10],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::PskKeyExchangeModes,
                        extension_data: ExtensionData::PskKeyExchangeModes(PskKeyExchangeModes {
                            ke_modes: vec![PskKeyExchangeMode::PskDheKe],
                        }),
                    }
                ]
            },
            &[
                0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x02, 0x01, 0x0F, 0x00, 0x04, 0x13, 0x03, 0x13,
                0x04, 0x01, 0x00, 0x00, 0x10, 0x00, 0x2C, 0x00, 0x06, 0x00, 0x04, 0x03, 0x0F, 0x04,
                0x10, 0x00, 0x2D, 0x00, 0x02, 0x01, 0x01,
            ]
        );

        // Negative
        // NOTE: Would be better to use slices
        let bytes = ByteParser::from(vec![]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello legacy version"
        ));

        let bytes = ByteParser::from(vec![0x04, 0x01]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello random length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello session id length"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello session_id length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello cipher_suites length"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x00, 0x01,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello cipher_suites length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x00, 0x01, 0x00,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello cipher suite"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x00, 0x02, 0x13, 0x03,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello compression methods length"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x00, 0x02, 0x13, 0x03, 0x01,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello compression methods length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x00, 0x02, 0x13, 0x03, 0x01, 0x00,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello extension length"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x00, 0x02, 0x13, 0x03, 0x01, 0x00,
            0x00, 0x01,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello extensions length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x00, 0x02, 0x13, 0x03, 0x01, 0x00,
            0x00, 0x01, 0x00,
        ]);
        assert!(ClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ClientHello Extension"
        ));
    }

    #[test]
    fn test_handshake_client_hello() {
        let handshake = Handshake {
            msg_type: HandshakeType::ClientHello,
            length: 55 as u32,
            message: HandshakeMessage::ClientHello(ClientHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                ],
                legacy_session_id: vec![0x04, 0x05],
                cipher_suites: vec![cipher_suites::TLS_CHACHA20_POLY1305_SHA256],
                legacy_compression_methods: vec![0x00],
                extensions: vec![Extension {
                    origin: ExtensionOrigin::Client,
                    extension_type: ExtensionType::Cookie,
                    extension_data: ExtensionData::Cookie(Cookie {
                        cookie: vec![0x13, 0x02, 0x09, 0xA0],
                    }),
                }],
            }),
        };
        let bytes = handshake.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, 0x00, 0x00, 0x37, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x02, 0x04, 0x05, 0x00,
                0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x2C, 0x00, 0x06, 0x00, 0x04, 0x13,
                0x02, 0x09, 0xA0,
            ]
        );
        let hs = Handshake::from_bytes(&mut ByteParser::from(bytes)).unwrap();
        assert_eq!(*hs, handshake);
    }

    #[test]
    fn test_server_hello() {
        // Positive
        round_trip!(
            ServerHello,
            ServerHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                ],
                legacy_session_id_echo: vec![0x01, 0x0F],
                cipher_suite: cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
                legacy_compression_method: 0x00,
                extensions: vec![
                    Extension {
                        origin: ExtensionOrigin::Server,
                        extension_type: ExtensionType::Cookie,
                        extension_data: ExtensionData::Cookie(Cookie {
                            cookie: vec![0x03, 0x0F, 0x04, 0x10],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Server,
                        extension_type: ExtensionType::PskKeyExchangeModes,
                        extension_data: ExtensionData::PskKeyExchangeModes(PskKeyExchangeModes {
                            ke_modes: vec![PskKeyExchangeMode::PskDheKe],
                        }),
                    }
                ]
            },
            &[
                0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x02, 0x01, 0x0F, 0x13, 0x03, 0x00, 0x00, 0x10,
                0x00, 0x2C, 0x00, 0x06, 0x00, 0x04, 0x03, 0x0F, 0x04, 0x10, 0x00, 0x2D, 0x00, 0x02,
                0x01, 0x01,
            ]
        );

        // Negative
        // NOTE: Would be better to use slices
        let bytes = ByteParser::from(vec![]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello legacy version"
        ));

        let bytes = ByteParser::from(vec![0x04, 0x01]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello random length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello session id length"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01,
        ]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello session_id length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00,
        ]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello cipher_suite length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x13, 0x03,
        ]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello compression method"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x13, 0x03, 0x00,
        ]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello extension length"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x13, 0x03, 0x00, 0x00, 0x01,
        ]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello extensions length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x04, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x01, 0x00, 0x13, 0x03, 0x00, 0x00, 0x01, 0x00,
        ]);
        assert!(ServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerHello Extension"
        ));
    }

    #[test]
    fn test_handshake_server_hello() {
        let handshake = Handshake {
            msg_type: HandshakeType::ServerHello,
            length: 52 as u32,
            message: HandshakeMessage::ServerHello(ServerHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                ],
                legacy_session_id_echo: vec![0x04, 0x05],
                cipher_suite: cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
                legacy_compression_method: 0x00,
                extensions: vec![Extension {
                    origin: ExtensionOrigin::Server,
                    extension_type: ExtensionType::Cookie,
                    extension_data: ExtensionData::Cookie(Cookie {
                        cookie: vec![0x13, 0x02, 0x09, 0xA0],
                    }),
                }],
            }),
        };
        let bytes = handshake.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x02, 0x00, 0x00, 0x34, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x02, 0x04, 0x05, 0x13,
                0x03, 0x00, 0x00, 0x0A, 0x00, 0x2C, 0x00, 0x06, 0x00, 0x04, 0x13, 0x02, 0x09, 0xA0,
            ]
        );
        let hs = Handshake::from_bytes(&mut ByteParser::from(bytes)).unwrap();
        assert_eq!(*hs, handshake);
    }

    #[test]
    fn test_certificate() {
        // Positive
        round_trip!(
            Certificate,
            Certificate {
                certificate_request_context: vec![0x04, 0xFF, 0xC3, 0xF1, 0x00, 0x2C],
                certificate_list: vec![
                    CertificateEntry {
                        certificate_type: CertificateType::X509,
                        certificate_data: vec![0x03, 0x1D, 0x51, 0x0F],
                        extensions: vec![
                            Extension {
                                origin: ExtensionOrigin::Server,
                                extension_type: ExtensionType::PskKeyExchangeModes,
                                extension_data: ExtensionData::PskKeyExchangeModes(
                                    PskKeyExchangeModes {
                                        ke_modes: vec![PskKeyExchangeMode::PskDheKe],
                                    }
                                ),
                            },
                            Extension {
                                origin: ExtensionOrigin::Server,
                                extension_type: ExtensionType::KeyShare,
                                extension_data: ExtensionData::KeyShareServerHello(
                                    KeyShareServerHello {
                                        server_share: KeyShareEntry {
                                            group: NamedGroup::Secp384r1,
                                            key_exchange: vec![0x44, 0x33, 0x55, 0xCC],
                                        },
                                    }
                                ),
                            }
                        ]
                    },
                    CertificateEntry {
                        certificate_type: CertificateType::X509,
                        certificate_data: vec![0x03, 0x1D, 0x51, 0x0F],
                        extensions: vec![Extension {
                            origin: ExtensionOrigin::Server,
                            extension_type: ExtensionType::SignatureAlgorithms,
                            extension_data: ExtensionData::SignatureAlgorithms(
                                SupportedSignatureAlgorithms {
                                    supported_signature_algorithms: vec![
                                        SignatureScheme::Ed25519,
                                        SignatureScheme::EcdsaSha1,
                                    ],
                                }
                            ),
                        }]
                    }
                ]
            },
            &[
                0x06, 0x04, 0xFF, 0xC3, 0xF1, 0x00, 0x2C, 0x00, 0x00, 0x2E, 0x00, 0x00, 0x04, 0x03,
                0x1D, 0x51, 0x0F, 0x00, 0x12, 0x00, 0x2D, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00,
                0x08, 0x00, 0x18, 0x00, 0x04, 0x44, 0x33, 0x55, 0xCC, 0x00, 0x00, 0x04, 0x03, 0x1D,
                0x51, 0x0F, 0x00, 0x0A, 0x00, 0x0D, 0x00, 0x06, 0x00, 0x04, 0x08, 0x07, 0x02, 0x03
            ]
        );

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(Certificate::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid certificate request context length"
        ));

        let bytes = ByteParser::from(vec![0x01]);
        assert!(Certificate::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid certificate_request_context length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![0x01, 0x00]);
        assert!(Certificate::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid certificate list length"
        ));

        let bytes = ByteParser::from(vec![0x01, 0x00, 0x00, 0x00, 0x01]);
        assert!(Certificate::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid CertificateEntry certification data length"
        ));

        let bytes = ByteParser::from(vec![0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01]);
        assert!(Certificate::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid certificate_data length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00]);
        assert!(Certificate::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid CertificateEntry extension length"
        ));

        let bytes = ByteParser::from(vec![
            0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01,
        ]);
        assert!(Certificate::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid Certificate extensions length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![
            0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
        ]);
        assert!(Certificate::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Certificate::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid Certificate Extension"
        ));
    }

    #[test]
    fn test_handshake_certificate() {
        let handshake = Handshake {
            msg_type: HandshakeType::Certificate,
            length: 23 as u32,
            message: HandshakeMessage::Certificate(Certificate {
                certificate_request_context: vec![0x03, 0x01, 0x0A],
                certificate_list: vec![CertificateEntry {
                    certificate_type: CertificateType::X509,
                    certificate_data: vec![0x00, 0x01, 0x02, 0x03, 0x04],
                    extensions: vec![Extension {
                        origin: ExtensionOrigin::Server,
                        extension_type: ExtensionType::SupportedVersions,
                        extension_data: ExtensionData::SupportedVersions(SupportedVersions {
                            version: VersionKind::Selected(0x22FF),
                        }),
                    }],
                }],
            }),
        };
        let bytes = handshake.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x0B, 0x00, 0x00, 0x17, 0x03, 0x03, 0x01, 0x0A, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x06, 0x00, 0x2B, 0x00, 0x02, 0x22, 0xFF
            ]
        );
        let hs = Handshake::from_bytes(&mut ByteParser::from(bytes)).unwrap();
        assert_eq!(*hs, handshake);
    }

    #[test]
    fn test_encrypted_extensions() {
        // Positive
        round_trip!(
            EncryptedExtensions,
            EncryptedExtensions {
                extensions: vec![
                    Extension {
                        origin: ExtensionOrigin::Server,
                        extension_type: ExtensionType::ServerName,
                        extension_data: ExtensionData::ServerName(ServerNameList {
                            server_name_list: vec![ServerName {
                                name_type: NameType::HostName,
                                host_name: "another.domain.net".as_bytes().to_vec(),
                            }],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Server,
                        extension_type: ExtensionType::Cookie,
                        extension_data: ExtensionData::Cookie(Cookie {
                            cookie: vec![0x03, 0x0F, 0x04, 0x10],
                        }),
                    }
                ]
            },
            &[
                0x00, 0x25, 0x00, 0x00, 0x00, 0x17, 0x00, 0x15, 0x00, 0x00, 0x12, 0x61, 0x6E, 0x6F,
                0x74, 0x68, 0x65, 0x72, 0x2E, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x6E, 0x65,
                0x74, 0x00, 0x2C, 0x00, 0x06, 0x00, 0x04, 0x03, 0x0F, 0x04, 0x10
            ]
        );

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(EncryptedExtensions::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            EncryptedExtensions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            EncryptedExtensions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid EncryptedExtensions extension length"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x01]);
        assert!(EncryptedExtensions::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            EncryptedExtensions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            EncryptedExtensions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid EncryptedExtensions extensions length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x01, 0x00]);
        assert!(EncryptedExtensions::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            EncryptedExtensions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            EncryptedExtensions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid EncryptedExtensions Extension"
        ));
    }

    #[test]
    fn test_handshake_encrypted_extensions() {
        let handshake = Handshake {
            msg_type: HandshakeType::EncryptedExtensions,
            length: 14 as u32,
            message: HandshakeMessage::EncryptedExtensions(EncryptedExtensions {
                extensions: vec![Extension {
                    origin: ExtensionOrigin::Server,
                    extension_type: ExtensionType::KeyShare,
                    extension_data: ExtensionData::KeyShareServerHello(KeyShareServerHello {
                        server_share: KeyShareEntry {
                            group: NamedGroup::Secp384r1,
                            key_exchange: vec![0x44, 0x33, 0x55, 0xCC],
                        },
                    }),
                }],
            }),
        };
        let bytes = handshake.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x08, 0x00, 0x00, 0x0E, 0x00, 0x0C, 0x00, 0x33, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04,
                0x44, 0x33, 0x55, 0xCC
            ]
        );
        let hs = Handshake::from_bytes(&mut ByteParser::from(bytes)).unwrap();
        assert_eq!(*hs, handshake);
    }

    #[test]
    fn test_certificate_verify() {
        // Positive
        round_trip!(
            CertificateVerify,
            CertificateVerify {
                algorithm: SignatureScheme::EcdsaSecp384r1Sha384,
                signature: vec![0x45, 0x67, 0xAC, 0xF4, 0x9D]
            },
            &[0x05, 0x03, 0x00, 0x05, 0x45, 0x67, 0xAC, 0xF4, 0x9D]
        );

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(CertificateVerify::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            CertificateVerify::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            CertificateVerify::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid CertificateVerify SignatureScheme"
        ));

        let bytes = ByteParser::from(vec![0x04, 0x01]);
        assert!(CertificateVerify::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            CertificateVerify::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            CertificateVerify::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid CertificateVerify signature length"
        ));

        let bytes = ByteParser::from(vec![0x04, 0x01, 0x00, 0x01]);
        assert!(CertificateVerify::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            CertificateVerify::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            CertificateVerify::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid CertificateVerifty signature length: buffer overflow"
        ));
    }

    #[test]
    fn test_handshake_certificate_verify() {
        let handshake = Handshake {
            msg_type: HandshakeType::CertificateVerify,
            length: 8 as u32,
            message: HandshakeMessage::CertificateVerify(CertificateVerify {
                algorithm: SignatureScheme::EcdsaSecp256r1Sha256,
                signature: vec![0xF4, 0xC1, 0x55, 0x9D],
            }),
        };
        let bytes = handshake.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![0x0F, 0x00, 0x00, 0x08, 0x04, 0x03, 0x00, 0x04, 0xF4, 0xC1, 0x55, 0x9D]
        );
        let hs = Handshake::from_bytes(&mut ByteParser::from(bytes)).unwrap();
        assert_eq!(*hs, handshake);
    }
}
