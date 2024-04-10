//! # TLS Extensions and their encoding/decoding
//!
//! Includes `ByteSerializable` trait for converting structures into bytes and constructing again.
use crate::handshake::ProtocolVersion;
use crate::parser::ByteParser;
use ::log::{debug, warn};

/// `ByteSerializable` trait is used to serialize and deserialize the struct into bytes
pub trait ByteSerializable {
    /// Returns the byte representation of the object if possible
    fn as_bytes(&self) -> Option<Vec<u8>>;
    /// Attempts to parse the bytes into a struct object implementing this trait
    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>>;
}

/// Helper to identify the origin of the extension (client or server)
/// Extension data format is different for client and server on some cases
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ExtensionOrigin {
    Client,
    Server,
}

/// `Extension` is wrapper for any TLS extension
#[derive(Debug, Clone, PartialEq)]
pub struct Extension {
    pub origin: ExtensionOrigin,
    pub extension_type: ExtensionType, // Defined maximum value can be 65535, takes 2 bytes to present
    pub extension_data: ExtensionData, // length of the data can be 0..2^16-1 (2 bytes to present)
}

impl Extension {
    pub(crate) fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice((self.extension_type as u16).to_be_bytes().as_ref());
        let ext_bytes = self.extension_data.as_bytes()?;
        // 2 byte length determinant for the `extension_data`
        bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
        bytes.extend_from_slice(&ext_bytes);
        Some(bytes)
    }

    pub(crate) fn from_bytes(
        bytes: &mut ByteParser,
        origin: ExtensionOrigin,
    ) -> std::io::Result<Box<Self>> {
        let ext_type = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid extension type")
        })?;

        debug!("ExtensionType: {:?}", ext_type);

        let ext_data_len = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid extension data length",
            )
        })?;

        debug!("Extension data length: {}", ext_data_len);

        let ext_data = bytes.get_bytes(ext_data_len as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid Extensions length: buffer overflow",
            )
        })?;
        let mut ext_bytes = ByteParser::from(ext_data);

        let extension_data = match ext_type {
            0 => ExtensionData::ServerName(*ServerNameList::from_bytes(&mut ext_bytes).map_err(
                |_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ExtensionData ServerNameList",
                    )
                },
            )?),
            10 => ExtensionData::SupportedGroups(
                *NamedGroupList::from_bytes(&mut ext_bytes).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ExtensionData SupportedGroups",
                    )
                })?,
            ),
            13 => ExtensionData::SignatureAlgorithms(
                *SupportedSignatureAlgorithms::from_bytes(&mut ext_bytes).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ExtensionData SignatureAlgorithms",
                    )
                })?,
            ),
            43 => ExtensionData::SupportedVersions(
                *SupportedVersions::from_bytes(&mut ext_bytes).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ExtensionData SupportedVersions",
                    )
                })?,
            ),
            44 => ExtensionData::Cookie(*Cookie::from_bytes(&mut ext_bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ExtensionData Cookie",
                )
            })?),
            45 => ExtensionData::PskKeyExchangeModes(
                *PskKeyExchangeModes::from_bytes(&mut ext_bytes).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ExtensionData PskKeyExchangeModes",
                    )
                })?,
            ),
            51 if origin == ExtensionOrigin::Server => ExtensionData::KeyShareServerHello(
                *KeyShareServerHello::from_bytes(&mut ext_bytes).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ExtensionData KeyShareServerHello",
                    )
                })?,
            ),
            51 if origin == ExtensionOrigin::Client => ExtensionData::KeyShareClientHello(
                *KeyShareClientHello::from_bytes(&mut ext_bytes).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid ExtensionData KeyShareClientHello",
                    )
                })?,
            ),
            _ => {
                warn!("Unknown ExtensionType: {}", ext_type);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid extension data",
                ));
            }
        };

        Ok(Box::new(Extension {
            origin,
            extension_type: ext_type.into(),
            extension_data,
        }))
    }
}

/// `ExtensionType` where maximum value can be 2^16-1 (2 bytes to present)
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
}

/// By using `From` trait, we can convert `u16` to `ExtensionType`, e.g. by using `.into()`
impl From<u16> for ExtensionType {
    fn from(value: u16) -> Self {
        match value {
            0 => ExtensionType::ServerName,
            1 => ExtensionType::MaxFragmentLength,
            5 => ExtensionType::StatusRequest,
            10 => ExtensionType::SupportedGroups,
            13 => ExtensionType::SignatureAlgorithms,
            14 => ExtensionType::UseSrtp,
            15 => ExtensionType::Heartbeat,
            16 => ExtensionType::ApplicationLayerProtocolNegotiation,
            18 => ExtensionType::SignedCertificateTimestamp,
            19 => ExtensionType::ClientCertificateType,
            20 => ExtensionType::ServerCertificateType,
            21 => ExtensionType::Padding,
            41 => ExtensionType::PreSharedKey,
            42 => ExtensionType::EarlyData,
            43 => ExtensionType::SupportedVersions,
            44 => ExtensionType::Cookie,
            45 => ExtensionType::PskKeyExchangeModes,
            47 => ExtensionType::CertificateAuthorities,
            48 => ExtensionType::OidFilters,
            49 => ExtensionType::PostHandshakeAuth,
            50 => ExtensionType::SignatureAlgorithmsCert,
            51 => ExtensionType::KeyShare,
            _ => {
                warn!("Unknown ExtensionType: {}", value);
                ExtensionType::ServerName
            }
        }
    }
}

/// `ExtensionData` is a wrapper for any data in the extension
/// TODO not all extension data types are implemented or added
/// Missing: signature_algorithms_cert(?), pre-shared key(?)
/// If no "signature_algorithms_cert" extension is present,
/// then the "signature_algorithms" extension also applies to signatures appearing in certificates.
/// All implementations MUST send and use these extensions when offering applicable features:
/// "pre_shared_key" is REQUIRED for PSK key agreement.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionData {
    ServerName(ServerNameList),
    SupportedGroups(NamedGroupList),
    SignatureAlgorithms(SupportedSignatureAlgorithms),
    SupportedVersions(SupportedVersions),
    KeyShareClientHello(KeyShareClientHello),
    KeyShareServerHello(KeyShareServerHello),
    PskKeyExchangeModes(PskKeyExchangeModes),
    Cookie(Cookie),
    //Unserialized(Vec<u8>), // TODO: Remove
}

impl ByteSerializable for ExtensionData {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            ExtensionData::ServerName(server_name_list) => server_name_list.as_bytes(),
            ExtensionData::SupportedGroups(named_group_list) => named_group_list.as_bytes(),
            ExtensionData::SignatureAlgorithms(supported_signature_algorithms) => {
                supported_signature_algorithms.as_bytes()
            }
            ExtensionData::SupportedVersions(supported_versions) => supported_versions.as_bytes(),
            ExtensionData::KeyShareClientHello(key_share_client_hello) => {
                key_share_client_hello.as_bytes()
            }
            ExtensionData::KeyShareServerHello(key_share_server_hello) => {
                key_share_server_hello.as_bytes()
            }
            ExtensionData::PskKeyExchangeModes(psk_key_exchange_modes) => {
                psk_key_exchange_modes.as_bytes()
            }
            ExtensionData::Cookie(cookie) => cookie.as_bytes(),
            /*_ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ExtensionData",
            )),*/
            //ExtensionData::Unserialized(data) => Some(data.clone()),
        }
    }

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("ExtensionData from_bytes() not implemented")
        // NOTE: This is not needed because Extension::from_bytes() calls specific extensions from_bytes() directly
        // NOTE: Also no idea how this would be implemented
    }
}

/// Kinds of `ProtocolVersion` - client offers multiple versions where a server selects one.
//#[derive(Debug, Clone)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionKind {
    Suggested(Vec<ProtocolVersion>), // length of the data can be 2..254 on client, 1 byte to present
    Selected(ProtocolVersion),
}

/// # Supported versions extension
//#[derive(Debug, Clone)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedVersions {
    pub version: VersionKind,
}

impl ByteSerializable for SupportedVersions {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();

        match &self.version {
            VersionKind::Suggested(versions) => {
                for version in versions {
                    bytes.extend_from_slice(&version.to_be_bytes());
                }

                // 1 byte length determinant for `versions`
                bytes.splice(
                    0..0,
                    u8::try_from(bytes.len())
                        .ok()?
                        .to_be_bytes()
                        .iter()
                        .copied(),
                );
            }
            VersionKind::Selected(version) => {
                bytes.extend_from_slice(&version.to_be_bytes());
            }
        }

        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // It takes at least 3 bytes to present ClientHello
        // Not the best for validation, but it's a start
        // TODO: Split same way as KeyShareClientHello and KeyShareServerHello
        // NOTE: What if len() is 0
        if bytes.len() > 2 {
            // 1 byte length determinant for `versions`
            // NOTE: This error is never reached
            let length = bytes.get_u8().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid suggested versions length",
                )
            })?;

            // Suggested versions are two bytes each
            // This means length should be % 2 == 0
            // NOTE: length should be checked
            // NOTE: I have feeling this loop will cause problems in the future
            let mut i = 0;
            let mut versions = Vec::new();

            // Not the best way but a good start
            while i < length {
                let version = bytes.get_u16().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid suggested version",
                    )
                })?;
                versions.push(version);
                i += 2
            }

            Ok(Box::new(SupportedVersions {
                version: VersionKind::Suggested(versions),
            }))
        } else {
            // NOTE: Selected version must be one in the list sent by client. Case where it isn't shoud never happen
            // but should be checked just in case. That should probably be done in main.rs or handshake.rs. Not sure yet.
            // Server returns the selected version which is represented with two bytes
            let selected_version = bytes.get_u16().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid selected version")
            })?;

            Ok(Box::new(SupportedVersions {
                version: VersionKind::Selected(selected_version),
            }))
        }
    }
}

/// Server Name extension, as defined in [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066#section-3)
/// `HostName` contains the fully qualified DNS hostname of the server,
/// as understood by the client.  The hostname is represented as a byte
/// string using ASCII encoding without a trailing dot.  This allows the
/// support of internationalized domain names through the use of A-labels
/// defined in RFC5890.  DNS hostnames are case-insensitive.  The
/// algorithm to compare hostnames is described in RFC5890, Section
/// 2.3.2.4.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerName {
    pub name_type: NameType,
    pub host_name: HostName,
}

impl std::fmt::Display for ServerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = String::from_utf8_lossy(&self.host_name);
        writeln!(f, "{:?}: {}", self.name_type, name)
    }
}

/// `NameType` where maximum value be `u8::MAX` (1 byte)
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NameType {
    HostName = 0,
}

/// `HostName` is a byte string using ASCII encoding of host without a trailing dot
type HostName = Vec<u8>;

/// `ServerNameList` is a list of `ServerName` structures, where maximum length be `u16::MAX` (2 bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct ServerNameList {
    pub server_name_list: Vec<ServerName>,
}

impl std::fmt::Display for ServerNameList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for server_name in &self.server_name_list {
            writeln!(f, "{server_name}")?;
        }
        Ok(())
    }
}

impl ByteSerializable for ServerNameList {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        // A server that receives a client hello containing the "server_name" extension
        // MAY use the information contained in the extension to guide its selection of
        // an appropriate certificate to return to the client, and/or other aspects of security policy.
        // In this event, the server SHALL include an extension of type "server_name" in the (extended) server hello.
        // The "extension_data" field of this extension SHALL be empty.
        // If server_name_list is empty, assume above and return Ok
        // TODO: Create seperate extension for when server sends ServerNameList,
        // same way as KeyShareClientHello and KeyShareServerHello
        if self.server_name_list.is_empty() {
            return Some(bytes);
        }

        for server_name in &self.server_name_list {
            bytes.push(server_name.name_type as u8);
            // 2 byte length determinant for the ASCII byte presentation of the name
            bytes.extend_from_slice(
                u16::try_from(server_name.host_name.len())
                    .ok()?
                    .to_be_bytes()
                    .as_ref(),
            );
            bytes.extend_from_slice(&server_name.host_name);
        }

        // 2 byte length determinant for the whole `ServerNameList`
        bytes.splice(
            0..0,
            u16::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );

        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // A server that receives a client hello containing the "server_name" extension
        // MAY use the information contained in the extension to guide its selection of
        // an appropriate certificate to return to the client, and/or other aspects of security policy.
        // In this event, the server SHALL include an extension of type "server_name" in the (extended) server hello.
        // The "extension_data" field of this extension SHALL be empty.
        // If bytes is empty, assume above and return Ok
        if bytes.is_empty() {
            return Ok(Box::new(ServerNameList {
                server_name_list: Vec::new(),
            }));
        }

        // 2 byte length determinant for the whole `ServerNameList`
        let list_length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid server name list length",
            )
        })?;

        // NOTE: Stupid loop time
        let mut i = 0;
        let mut server_names = Vec::new();

        while i < list_length {
            // 1 byte for name_type, which is always 0
            let _name_type = bytes.get_u8().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid server name name type",
                )
            })?;

            // 2 byte length determinant for the ASCII byte presentation of the name
            let length = bytes.get_u16().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid server name host name length",
                )
            })?;

            let hostname = bytes.get_bytes(length as usize).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ServerNameList host_name length: buffer overflow",
                )
            })?;

            // NOTE: Should this have error check, or should that be in the get_bytes() method
            // TODO: Don't autoassume name_type == 0, test it
            server_names.push(ServerName {
                name_type: NameType::HostName,
                host_name: hostname,
            });

            // 1 byte for name_type + 2 bytes for host_name length determinant + length of host_name
            i += 1 + 2 + length
        }

        Ok(Box::new(ServerNameList {
            server_name_list: server_names,
        }))
    }
}

/// ## Signature Algorithm Extension
/// Our client primarily supports signature scheme Ed25519
/// Value takes 2 bytes to represent.
/// See more [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.3)
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,
    /* ECDSA algorithms */
    EcdsaSecp256r1Sha256 = 0x0403, // NOTE: Added support
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256 = 0x0804, // YES
    RsaPssRsaeSha384 = 0x0805, // YES
    RsaPssRsaeSha512 = 0x0806, // YES
    /* EdDSA algorithms */
    Ed25519 = 0x0807, // NOTE The only supported signature scheme. NOTE: Websites don't support
    Ed448 = 0x0808,
    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,
    /* Legacy algorithms */
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,
    /* Reserved Code Points */
    // PrivateUse(0xFE00..0xFFFF),
}

impl ByteSerializable for SignatureScheme {
    //noinspection DuplicatedCode
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match *self as u32 {
            #[allow(clippy::cast_possible_truncation)]
            value if u16::try_from(value).is_ok() => Some((value as u16).to_be_bytes().to_vec()),
            _ => None,
        }
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // SignatureScheme value is 2 bytes
        // NOTE: This feels very dumb, but I am not familiar with Rust
        match bytes.get_u16().ok_or_else(ByteParser::insufficient_data)? {
            0x0401 => Ok(Box::new(SignatureScheme::RsaPkcs1Sha256)),
            0x0501 => Ok(Box::new(SignatureScheme::RsaPkcs1Sha384)),
            0x0601 => Ok(Box::new(SignatureScheme::RsaPkcs1Sha512)),
            0x0403 => Ok(Box::new(SignatureScheme::EcdsaSecp256r1Sha256)), // NOTE: Actually the only supported signature scheme
            0x0503 => Ok(Box::new(SignatureScheme::EcdsaSecp384r1Sha384)),
            0x0603 => Ok(Box::new(SignatureScheme::EcdsaSecp521r1Sha512)),
            0x0804 => Ok(Box::new(SignatureScheme::RsaPssRsaeSha256)),
            0x0805 => Ok(Box::new(SignatureScheme::RsaPssRsaeSha384)),
            0x0806 => Ok(Box::new(SignatureScheme::RsaPssRsaeSha512)),
            0x0807 => Ok(Box::new(SignatureScheme::Ed25519)), // NOTE The only supported signature scheme // NOTE: Actually no
            0x0808 => Ok(Box::new(SignatureScheme::Ed448)),
            0x0809 => Ok(Box::new(SignatureScheme::RsaPssPssSha256)),
            0x080a => Ok(Box::new(SignatureScheme::RsaPssPssSha384)),
            0x080b => Ok(Box::new(SignatureScheme::RsaPssPssSha512)),
            0x0201 => Ok(Box::new(SignatureScheme::RsaPkcs1Sha1)),
            0x0203 => Ok(Box::new(SignatureScheme::EcdsaSha1)),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid SignatureScheme",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SupportedSignatureAlgorithms {
    pub supported_signature_algorithms: Vec<SignatureScheme>, // length of the data can be 2..2^16-2
}

impl ByteSerializable for SupportedSignatureAlgorithms {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();

        for signature_scheme in &self.supported_signature_algorithms {
            bytes.extend_from_slice(&signature_scheme.as_bytes()?);
        }

        // 2 byte length determinant for the whole `SupportedSignatureAlgorithms`
        bytes.splice(0..0, u16::try_from(bytes.len()).ok()?.to_be_bytes());
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // 2 byte length determinant for the whole `SupportedSignatureAlgorithms`
        let length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid supported signature algorithms length",
            )
        })?;

        // NOTE: Stupid loop time
        let mut i = 0;
        let mut signature_schemes = Vec::new();

        while i < length {
            // NOTE: I am not sure if this is a good idea
            signature_schemes.push(*SignatureScheme::from_bytes(bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid SupportedSignatureAlgorithms SignatureScheme",
                )
            })?);
            i += 2
        }

        Ok(Box::new(SupportedSignatureAlgorithms {
            supported_signature_algorithms: signature_schemes,
        }))
    }
}

/// ## Supported Groups Extension
/// Our client supports primarily Elliptic Curve Diffie-Hellman (ECDH) with Curve25519
/// Parameters for ECDH goes to opaque `key_exchange` field of a `KeyShareEntry` in a `KeyShare` structure.
/// Max size is (0xFFFF), takes 2 bytes to present
/// See more in [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.4)
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1 = 0x0017, // NOTE: We only support this
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D, // NOTE The only supported named group // NOTE: Not true
    X448 = 0x001E,
    /* Finite Field Groups (DHE) */
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
    /* Reserved Code Points */
    // ffdhe_private_use(0x01FC..0x01FF),
    // ecdhe_private_use(0xFE00..0xFEFF),
}

impl ByteSerializable for NamedGroup {
    //noinspection DuplicatedCode
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match *self as u32 {
            #[allow(clippy::cast_possible_truncation)]
            value if u16::try_from(value).is_ok() => Some((value as u16).to_be_bytes().to_vec()),
            _ => None,
        }
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        match bytes.get_u16().ok_or_else(ByteParser::insufficient_data)? {
            0x0017 => Ok(Box::new(NamedGroup::Secp256r1)),
            0x0018 => Ok(Box::new(NamedGroup::Secp384r1)),
            0x0019 => Ok(Box::new(NamedGroup::Secp521r1)),
            0x001D => Ok(Box::new(NamedGroup::X25519)),
            0x001E => Ok(Box::new(NamedGroup::X448)),
            0x0100 => Ok(Box::new(NamedGroup::Ffdhe2048)),
            0x0101 => Ok(Box::new(NamedGroup::Ffdhe3072)),
            0x0102 => Ok(Box::new(NamedGroup::Ffdhe4096)),
            0x0103 => Ok(Box::new(NamedGroup::Ffdhe6144)),
            0x0104 => Ok(Box::new(NamedGroup::Ffdhe8192)),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid NamedGroup",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NamedGroupList {
    pub named_group_list: Vec<NamedGroup>, // (2 bytes to present)
}

impl ByteSerializable for NamedGroupList {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();

        for named_group in &self.named_group_list {
            bytes.extend_from_slice(&named_group.as_bytes()?);
        }

        // 2 byte length determinant for `named_group_list`
        bytes.splice(
            0..0,
            u16::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );

        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // 2 byte length determinant for `named_group_list`
        let length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid named group list length",
            )
        })?;

        // NOTE: Stupid loop time
        let mut i = 0;
        let mut named_groups = Vec::new();

        while i < length {
            // NOTE: I am not sure if this is a good idea
            named_groups.push(*NamedGroup::from_bytes(bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid NamedGroupList NamedGroup",
                )
            })?);
            i += 2
        }

        Ok(Box::new(NamedGroupList {
            named_group_list: named_groups,
        }))
    }
}

/// ## `KeyShare` Extension
#[derive(Debug, Clone, PartialEq)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>, // (2 bytes to present the length)
}

impl ByteSerializable for KeyShareEntry {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(self.group.as_bytes()?);
        // 2 byte length determinant for the `key_exchange`
        bytes.extend(
            u16::try_from(self.key_exchange.len())
                .ok()?
                .to_be_bytes()
                .as_ref(),
        );
        bytes.extend_from_slice(&self.key_exchange);
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // NOTE: I am not sure if this is a good idea to do unchecked
        let named_group = *NamedGroup::from_bytes(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid KeyShareEntry NamedGroup",
            )
        })?;

        // 2 byte length determinant for the `key_exchange`
        let length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid key exchange length",
            )
        })?;

        let key_exchange = bytes.get_bytes(length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid KeyShareEntry key_exchange length: buffer overflow",
            )
        })?;

        Ok(Box::new(KeyShareEntry {
            group: named_group,
            key_exchange,
        }))
    }
}

/// There are three different structures for `KeyShare` extension
/// One for `ClientHello`, one for `HelloRetryRequest` and one for `ServerHello`
/// The order in the vector `KeyShareEntry` should be same as in `SupportedGroups` extension
#[derive(Debug, Clone, PartialEq)]
pub struct KeyShareClientHello {
    pub client_shares: Vec<KeyShareEntry>, // (2 bytes to present the length)
}

impl ByteSerializable for KeyShareClientHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();

        for client_share in &self.client_shares {
            bytes.extend_from_slice(&client_share.as_bytes()?);
        }

        // 2 byte length determinant for `client_shares`
        bytes.splice(
            0..0,
            u16::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );

        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // 2 byte length determinant for `client_shares`
        let length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid client shares length",
            )
        })?;

        // NOTE: Stupid loop time
        let mut i = 0;
        let mut key_shares = Vec::new();

        // NOTE: Length should be checked
        while i < length {
            // NOTE: Stupid but it is a start part 1
            let len = bytes.len();

            // NOTE: I am not sure if this is a good idea
            key_shares.push(*KeyShareEntry::from_bytes(bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid KeyShareClientHello KeyShareEntry",
                )
            })?);

            // NOTE: Stupid but it is a start part 2
            i += (len - bytes.len()) as u16
        }

        Ok(Box::new(KeyShareClientHello {
            client_shares: key_shares,
        }))
    }
}
/// `key_share` extension data structure in `ServerHello`
/// Contains only single `KeyShareEntry` when compared to `KeyShareClientHello`
#[derive(Debug, Clone, PartialEq)]
pub struct KeyShareServerHello {
    pub server_share: KeyShareEntry,
}

impl ByteSerializable for KeyShareServerHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        self.server_share.as_bytes()
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        Ok(Box::new(KeyShareServerHello {
            server_share: *KeyShareEntry::from_bytes(bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid KeyShareServerHello KeyShareEntry",
                )
            })?,
        }))
    }
}

/// Modes for pre-shared key (PSK) key exchange
/// Client-only
/// 1 byte to present
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}

/// ## `psk_key_exchange_modes` extension
/// A client MUST provide a `PskKeyExchangeModes` extension if it
///  offers a `pre_shared_key` extension.
#[derive(Debug, Clone, PartialEq)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vec<PskKeyExchangeMode>, // (1 byte to present the length)
}

impl ByteSerializable for PskKeyExchangeModes {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();

        for ke_mode in &self.ke_modes {
            bytes.push(*ke_mode as u8);
        }

        // 1 byte length determinant for `ke_modes`
        bytes.splice(
            0..0,
            u8::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );

        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // 1 byte length determinant for `ke_modes`
        let length = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid ke modes length")
        })?;

        // NOTE: Stupid loop time
        let mut i = 0;
        let mut ke_modes = Vec::new();

        // NOTE: Length should be checked
        while i < length {
            // PskKeyExchangeMode value is 1 byte
            // NOTE: This feels very dumb, but I am not familiar with Rust
            match bytes.get_u8().ok_or_else(ByteParser::insufficient_data)? {
                0 => ke_modes.push(PskKeyExchangeMode::PskKe),
                1 => ke_modes.push(PskKeyExchangeMode::PskDheKe),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid pre-shared Key exchange mode",
                    ))
                }
            }

            i += 1
        }

        Ok(Box::new(PskKeyExchangeModes { ke_modes: ke_modes }))
    }
}

/// ## Cookie extension
#[derive(Debug, Clone, PartialEq)]
pub struct Cookie {
    pub cookie: Vec<u8>, // (2 bytes to present the length)
}

impl ByteSerializable for Cookie {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        // 2 byte length determinant for the `cookie`
        bytes.extend(
            u16::try_from(self.cookie.len())
                .ok()?
                .to_be_bytes()
                .as_ref(),
        );
        bytes.extend_from_slice(&self.cookie);
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // 2 byte length determinant for the `key_exchange`
        let length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid cookie length")
        })?;

        let cookie = bytes.get_bytes(length as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid Cookie length: buffer overflow",
            )
        })?;

        Ok(Box::new(Cookie { cookie }))
    }
}

#[cfg(test)]
mod tests {
    // NOTE: ExtensionData tests not included due to incomplete implementation of from_bytes()
    use super::*;
    use crate::round_trip;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_extension() {
        // NOTE: Positive testing is included in test_extension_* functions
        // Negative
        let bytes = ByteParser::from(vec![0x0F]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid extension type"
        ));

        let bytes = ByteParser::from(vec![0x0F, 0x01, 0xDC]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid extension data length"
        ));

        let bytes = ByteParser::from(vec![0x0F, 0x01, 0xDC, 0xFF]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid Extensions length: buffer overflow"
        ));

        let bytes = ByteParser::from(vec![0x0F, 0x01, 0x00, 0x01, 0x00]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid extension data"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x00, 0x00, 0x01, 0x00]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid ExtensionData ServerNameList"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x0A, 0x00, 0x01, 0x00]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid ExtensionData SupportedGroups"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x0D, 0x00, 0x01, 0x00]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid ExtensionData SignatureAlgorithms"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x2B, 0x00, 0x01, 0x00]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid ExtensionData SupportedVersions"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x2C, 0x00, 0x01, 0x00]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid ExtensionData Cookie"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x2D, 0x00, 0x01, 0x05]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid ExtensionData PskKeyExchangeModes"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x33, 0x00, 0x01, 0x05]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Server,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Server),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Server),
            Err(ref e) if e.to_string() == "Invalid ExtensionData KeyShareServerHello"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x33, 0x00, 0x01, 0x05]);
        assert!(Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client,).is_err());
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Extension::from_bytes(&mut bytes.clone(), ExtensionOrigin::Client),
            Err(ref e) if e.to_string() == "Invalid ExtensionData KeyShareClientHello"
        ));
    }

    #[test]
    fn test_extension_type() {
        // NOTE: Dumb tests due to ExtensionType implementation
        // Positive
        assert_eq!(ExtensionType::from(0), ExtensionType::ServerName);
        assert_eq!(ExtensionType::from(1), ExtensionType::MaxFragmentLength);
        assert_eq!(ExtensionType::from(5), ExtensionType::StatusRequest);
        assert_eq!(ExtensionType::from(10), ExtensionType::SupportedGroups);
        assert_eq!(ExtensionType::from(13), ExtensionType::SignatureAlgorithms);
        assert_eq!(ExtensionType::from(14), ExtensionType::UseSrtp);
        assert_eq!(ExtensionType::from(15), ExtensionType::Heartbeat);
        assert_eq!(
            ExtensionType::from(16),
            ExtensionType::ApplicationLayerProtocolNegotiation
        );
        assert_eq!(
            ExtensionType::from(18),
            ExtensionType::SignedCertificateTimestamp
        );
        assert_eq!(
            ExtensionType::from(19),
            ExtensionType::ClientCertificateType
        );
        assert_eq!(
            ExtensionType::from(20),
            ExtensionType::ServerCertificateType
        );
        assert_eq!(ExtensionType::from(21), ExtensionType::Padding);
        assert_eq!(ExtensionType::from(41), ExtensionType::PreSharedKey);
        assert_eq!(ExtensionType::from(42), ExtensionType::EarlyData);
        assert_eq!(ExtensionType::from(43), ExtensionType::SupportedVersions);
        assert_eq!(ExtensionType::from(44), ExtensionType::Cookie);
        assert_eq!(ExtensionType::from(45), ExtensionType::PskKeyExchangeModes);
        assert_eq!(
            ExtensionType::from(47),
            ExtensionType::CertificateAuthorities
        );
        assert_eq!(ExtensionType::from(48), ExtensionType::OidFilters);
        assert_eq!(ExtensionType::from(49), ExtensionType::PostHandshakeAuth);
        assert_eq!(
            ExtensionType::from(50),
            ExtensionType::SignatureAlgorithmsCert
        );
        assert_eq!(ExtensionType::from(51), ExtensionType::KeyShare);

        //Negative
        assert_eq!(ExtensionType::from(2), ExtensionType::ServerName);
        assert_eq!(ExtensionType::from(3), ExtensionType::ServerName);
        assert_eq!(ExtensionType::from(4), ExtensionType::ServerName);
    }

    #[test]
    fn test_supported_versions() {
        // Positive
        round_trip!(
            SupportedVersions,
            SupportedVersions {
                version: VersionKind::Selected(0x1a1b)
            },
            &[0x1a, 0x1b]
        );

        round_trip!(
            SupportedVersions,
            SupportedVersions {
                version: VersionKind::Suggested(vec![0x74B1, 0x9AF0])
            },
            &[0x04, 0x74, 0xB1, 0x9A, 0xF0]
        );

        // Negative
        // VersionKind::Selected
        let bytes = ByteParser::from(vec![]);
        assert!(SupportedVersions::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            SupportedVersions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            SupportedVersions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid selected version"
        ));

        let bytes = ByteParser::from(vec![0x00]);
        assert!(SupportedVersions::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            SupportedVersions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            SupportedVersions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid selected version"
        ));

        // VersionKind::Suggested
        let bytes = ByteParser::from(vec![0x04, 0x02, 0x03, 0x01]);
        assert!(SupportedVersions::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            SupportedVersions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            SupportedVersions::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid suggested version"
        ));
    }

    #[test]
    fn test_extension_supported_versions() {
        let extension = Extension {
            origin: ExtensionOrigin::Server,
            extension_type: ExtensionType::SupportedVersions,
            extension_data: ExtensionData::SupportedVersions(SupportedVersions {
                version: VersionKind::Selected(0x22FF),
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(bytes, vec![0x00, 0x2B, 0x00, 0x02, 0x22, 0xFF]);
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Server).unwrap();
        assert_eq!(*ext, extension);

        let extension = Extension {
            origin: ExtensionOrigin::Client,
            extension_type: ExtensionType::SupportedVersions,
            extension_data: ExtensionData::SupportedVersions(SupportedVersions {
                version: VersionKind::Suggested(vec![0x22FF, 0x1D09, 0x40A1]),
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![0x00, 0x2B, 0x00, 0x07, 0x06, 0x22, 0xFF, 0x1D, 0x09, 0x40, 0xA1]
        );
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Client).unwrap();
        assert_eq!(*ext, extension);
    }

    #[test]
    fn test_server_name_list() {
        // Positive
        round_trip!(
            ServerNameList,
            ServerNameList {
                server_name_list: vec![
                    ServerName {
                        name_type: NameType::HostName,
                        host_name: "example.domain.org".as_bytes().to_vec(),
                    },
                    ServerName {
                        name_type: NameType::HostName,
                        host_name: "example.website.com".as_bytes().to_vec(),
                    }
                ],
            },
            &[
                0x00, 0x2B, 0x00, 0x00, 0x12, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x64,
                0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x6F, 0x72, 0x67, 0x00, 0x00, 0x13, 0x65, 0x78,
                0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x77, 0x65, 0x62, 0x73, 0x69, 0x74, 0x65, 0x2E,
                0x63, 0x6F, 0x6D
            ]
        );

        round_trip!(
            ServerNameList,
            ServerNameList {
                server_name_list: Vec::new(),
            },
            &[]
        );

        //Negative
        let bytes = ByteParser::from(vec![0x01]);
        assert!(ServerNameList::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerNameList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerNameList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid server name list length"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x01]);
        assert!(ServerNameList::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerNameList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerNameList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid server name name type"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x01, 0x00, 0x00]);
        assert!(ServerNameList::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerNameList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerNameList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid server name host name length"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x01, 0x00, 0x00, 0x01]);
        assert!(ServerNameList::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            ServerNameList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            ServerNameList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ServerNameList host_name length: buffer overflow"
        ));
    }

    #[test]
    fn test_extension_server_name_list() {
        let extension = Extension {
            origin: ExtensionOrigin::Client,
            extension_type: ExtensionType::ServerName,
            extension_data: ExtensionData::ServerName(ServerNameList {
                server_name_list: vec![ServerName {
                    name_type: NameType::HostName,
                    host_name: "another.domain.net".as_bytes().to_vec(),
                }],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x00, 0x00, 0x00, 0x17, 0x00, 0x15, 0x00, 0x00, 0x12, 0x61, 0x6E, 0x6F, 0x74, 0x68,
                0x65, 0x72, 0x2E, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x6E, 0x65, 0x74
            ]
        );
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Client).unwrap();
        assert_eq!(*ext, extension);
    }

    #[test]
    fn test_signature_scheme() {
        // Positive
        round_trip!(
            SignatureScheme,
            SignatureScheme::EcdsaSecp256r1Sha256,
            &[0x04, 0x03]
        );

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(SignatureScheme::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            SignatureScheme::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            SignatureScheme::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Insufficient data when parsing input bytes"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x00]);
        assert!(SignatureScheme::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            SignatureScheme::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            SignatureScheme::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid SignatureScheme"
        ));
    }

    #[test]
    fn test_supported_signature_algorithms() {
        // Positive
        round_trip!(
            SupportedSignatureAlgorithms,
            SupportedSignatureAlgorithms {
                supported_signature_algorithms: vec![
                    SignatureScheme::EcdsaSecp384r1Sha384,
                    SignatureScheme::EcdsaSecp521r1Sha512
                ]
            },
            &[0x00, 0x04, 0x05, 0x03, 0x06, 0x03]
        );

        // Negative
        let bytes = ByteParser::from(vec![0x00]);
        assert!(SupportedSignatureAlgorithms::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            SupportedSignatureAlgorithms::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            SupportedSignatureAlgorithms::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid supported signature algorithms length"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x01]);
        assert!(SupportedSignatureAlgorithms::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            SupportedSignatureAlgorithms::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            SupportedSignatureAlgorithms::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid SupportedSignatureAlgorithms SignatureScheme"
        ));
    }

    #[test]
    fn test_extension_supported_signature_algorithms() {
        let extension = Extension {
            origin: ExtensionOrigin::Client,
            extension_type: ExtensionType::SignatureAlgorithms,
            extension_data: ExtensionData::SignatureAlgorithms(SupportedSignatureAlgorithms {
                supported_signature_algorithms: vec![
                    SignatureScheme::Ed25519,
                    SignatureScheme::EcdsaSha1,
                ],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![0x00, 0x0D, 0x00, 0x06, 0x00, 0x04, 0x08, 0x07, 0x02, 0x03]
        );
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Client).unwrap();
        assert_eq!(*ext, extension);
    }

    #[test]
    fn test_named_group() {
        // Positive
        round_trip!(NamedGroup, NamedGroup::X25519, &[0x00, 0x1D]);

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(NamedGroup::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            NamedGroup::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            NamedGroup::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Insufficient data when parsing input bytes"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x00]);
        assert!(NamedGroup::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            NamedGroup::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            NamedGroup::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid NamedGroup"
        ));
    }

    #[test]
    fn test_named_group_list() {
        // Positive
        round_trip!(
            NamedGroupList,
            NamedGroupList {
                named_group_list: vec![NamedGroup::X448, NamedGroup::Ffdhe4096]
            },
            &[0x00, 0x04, 0x00, 0x1E, 0x01, 0x02]
        );

        // Negative
        let bytes = ByteParser::from(vec![0x00]);
        assert!(NamedGroupList::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            NamedGroupList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            NamedGroupList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid named group list length"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x01]);
        assert!(NamedGroupList::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            NamedGroupList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            NamedGroupList::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid NamedGroupList NamedGroup"
        ));
    }

    #[test]
    fn test_extension_named_group_list() {
        let extension = Extension {
            origin: ExtensionOrigin::Client,
            extension_type: ExtensionType::SupportedGroups,
            extension_data: ExtensionData::SupportedGroups(NamedGroupList {
                named_group_list: vec![NamedGroup::Ffdhe2048],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(bytes, vec![0x00, 0x0A, 0x00, 0x04, 0x00, 0x02, 0x01, 0x00]);
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Client).unwrap();
        assert_eq!(*ext, extension);
    }

    #[test]
    fn test_key_share_entry() {
        // Positive
        round_trip!(
            KeyShareEntry,
            KeyShareEntry {
                group: NamedGroup::Secp256r1,
                key_exchange: vec![0xFF, 0x4D, 0x56]
            },
            &[0x00, 0x17, 0x00, 0x03, 0xFF, 0x4D, 0x56]
        );

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(KeyShareEntry::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            KeyShareEntry::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            KeyShareEntry::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid KeyShareEntry NamedGroup"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x17, 0x01]);
        assert!(KeyShareEntry::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            KeyShareEntry::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            KeyShareEntry::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid key exchange length"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x17, 0x00, 0x01]);
        assert!(KeyShareEntry::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            KeyShareEntry::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            KeyShareEntry::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid KeyShareEntry key_exchange length: buffer overflow"
        ));
    }

    #[test]
    fn test_key_share_client_hello() {
        // Positive
        round_trip!(
            KeyShareClientHello,
            KeyShareClientHello {
                client_shares: vec![
                    KeyShareEntry {
                        group: NamedGroup::X25519,
                        key_exchange: vec![0x00, 0x02, 0x32, 0x5B],
                    },
                    KeyShareEntry {
                        group: NamedGroup::Ffdhe4096,
                        key_exchange: vec![0x00, 0x03, 0xFF, 0x0C, 0x13]
                    }
                ]
            },
            &[
                0x00, 0x11, 0x00, 0x1D, 0x00, 0x04, 0x00, 0x02, 0x32, 0x5B, 0x01, 0x02, 0x00, 0x05,
                0x00, 0x03, 0xFF, 0x0C, 0x13
            ]
        );

        // Negative
        let bytes = ByteParser::from(vec![0x17]);
        assert!(KeyShareClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            KeyShareClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            KeyShareClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid client shares length"
        ));

        let bytes = ByteParser::from(vec![0x00, 0x02]);
        assert!(KeyShareClientHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            KeyShareClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            KeyShareClientHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid KeyShareClientHello KeyShareEntry"
        ));
    }

    #[test]
    fn test_extension_key_share_client_hello() {
        let extension = Extension {
            origin: ExtensionOrigin::Client,
            extension_type: ExtensionType::KeyShare,
            extension_data: ExtensionData::KeyShareClientHello(KeyShareClientHello {
                client_shares: vec![KeyShareEntry {
                    group: NamedGroup::Secp521r1,
                    key_exchange: vec![0x00, 0x04, 0xD3, 0x5C, 0x12, 0x07],
                }],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x00, 0x33, 0x00, 0x0C, 0x00, 0x0A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x04, 0xD3, 0x5C,
                0x12, 0x07
            ]
        );
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Client).unwrap();
        assert_eq!(*ext, extension);
    }

    #[test]
    fn test_key_share_server_hello() {
        // Positive
        round_trip!(
            KeyShareServerHello,
            KeyShareServerHello {
                server_share: KeyShareEntry {
                    group: NamedGroup::Ffdhe6144,
                    key_exchange: vec![0x80, 0x54, 0x2F, 0xE1]
                }
            },
            &[0x01, 0x03, 0x00, 0x04, 0x80, 0x54, 0x2F, 0xE1]
        );

        // Negative
        let bytes = ByteParser::from(vec![0x17]);
        assert!(KeyShareServerHello::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            KeyShareServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            KeyShareServerHello::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid KeyShareServerHello KeyShareEntry"
        ));
    }

    #[test]
    fn test_extension_key_share_server_hello() {
        let extension = Extension {
            origin: ExtensionOrigin::Server,
            extension_type: ExtensionType::KeyShare,
            extension_data: ExtensionData::KeyShareServerHello(KeyShareServerHello {
                server_share: KeyShareEntry {
                    group: NamedGroup::Secp384r1,
                    key_exchange: vec![0x44, 0x33, 0x55, 0xCC],
                },
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![0x00, 0x33, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x44, 0x33, 0x55, 0xCC]
        );
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Server).unwrap();
        assert_eq!(*ext, extension);
    }

    #[test]
    fn test_psk_key_exchange_modes() {
        // Positive
        round_trip!(
            PskKeyExchangeModes,
            PskKeyExchangeModes {
                ke_modes: vec![PskKeyExchangeMode::PskKe, PskKeyExchangeMode::PskDheKe]
            },
            &[0x02, 0x00, 0x01]
        );

        // Negative
        let bytes = ByteParser::from(vec![]);
        assert!(PskKeyExchangeModes::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            PskKeyExchangeModes::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            PskKeyExchangeModes::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid ke modes length"
        ));

        let bytes = ByteParser::from(vec![0x01]);
        assert!(PskKeyExchangeModes::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            PskKeyExchangeModes::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            PskKeyExchangeModes::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Insufficient data when parsing input bytes"
        ));

        let bytes = ByteParser::from(vec![0x01, 0x03]);
        assert!(PskKeyExchangeModes::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            PskKeyExchangeModes::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            PskKeyExchangeModes::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid pre-shared Key exchange mode"
        ));
    }

    #[test]
    fn test_extension_psk_key_exchange_modes() {
        let extension = Extension {
            origin: ExtensionOrigin::Server,
            extension_type: ExtensionType::PskKeyExchangeModes,
            extension_data: ExtensionData::PskKeyExchangeModes(PskKeyExchangeModes {
                ke_modes: vec![PskKeyExchangeMode::PskDheKe],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(bytes, vec![0x00, 0x2D, 0x00, 0x02, 0x01, 0x01]);
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Server).unwrap();
        assert_eq!(*ext, extension);
    }

    #[test]
    fn test_cookie() {
        // Positive
        round_trip!(
            Cookie,
            Cookie {
                cookie: vec![0x12, 0x13, 0x14, 0x15]
            },
            &[0x00, 0x04, 0x12, 0x13, 0x14, 0x15]
        );

        // Negative
        let bytes = ByteParser::from(vec![0xCE]);
        assert!(Cookie::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Cookie::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Cookie::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid cookie length"
        ));

        // Negative
        let bytes = ByteParser::from(vec![0x00, 0x02]);
        assert!(Cookie::from_bytes(&mut bytes.clone(),).is_err());
        assert!(matches!(
            Cookie::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Cookie::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid Cookie length: buffer overflow"
        ));
    }

    #[test]
    fn test_extension_cookie() {
        let extension = Extension {
            origin: ExtensionOrigin::Server,
            extension_type: ExtensionType::Cookie,
            extension_data: ExtensionData::Cookie(Cookie {
                cookie: vec![0x03, 0x0F, 0x04, 0x10],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![0x00, 0x2C, 0x00, 0x06, 0x00, 0x04, 0x03, 0x0F, 0x04, 0x10]
        );
        let ext =
            Extension::from_bytes(&mut ByteParser::from(bytes), ExtensionOrigin::Server).unwrap();
        assert_eq!(*ext, extension);
    }

    #[test]
    fn old_test_server_name_list() {
        let server_name_list = ServerNameList {
            server_name_list: vec![ServerName {
                name_type: NameType::HostName,
                host_name: "example.ulfheim.net".as_bytes().to_vec(),
            }],
        };
        let bytes = server_name_list.as_bytes().unwrap();
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            bytes,
            vec![
                0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75,
                0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74
            ]
        );
    }

    #[test]
    fn old_test_extension_server_name_list() {
        let extension = Extension {
            origin: ExtensionOrigin::Client,
            extension_type: ExtensionType::ServerName,
            extension_data: ExtensionData::ServerName(ServerNameList {
                server_name_list: vec![ServerName {
                    name_type: NameType::HostName,
                    host_name: "example.ulfheim.net".as_bytes().to_vec(),
                }],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70,
                0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74
            ]
        );
    }
}
