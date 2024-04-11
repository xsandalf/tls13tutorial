#![allow(dead_code)]
use hmac::digest::MacError;
use log::{debug, error, info, warn};
use pretty_assertions::assert_eq;
#[cfg(not(debug_assertions))]
use rand::rngs::OsRng;
use std::collections::VecDeque;
use std::io::{self, Read as SocketRead, Write as SocketWrite};
use std::net::TcpStream;
use std::str;
use std::time::Duration;
use std::time::SystemTime;
use std::vec;
use tls13tutorial::alert::Alert;
use tls13tutorial::display::to_hex;
use tls13tutorial::extensions::{
    ByteSerializable, Extension, ExtensionData, ExtensionOrigin, ExtensionType,
    KeyShareClientHello, KeyShareEntry, NameType, NamedGroup, NamedGroupList, ServerName,
    ServerNameList, SignatureScheme, SupportedSignatureAlgorithms, SupportedVersions, VersionKind,
};
use tls13tutorial::handshake::{
    cipher_suites, ClientHello, Finished, Handshake, HandshakeMessage, HandshakeType, Random,
    TLS_VERSION_1_3, TLS_VERSION_COMPATIBILITY,
};
use tls13tutorial::parser::ByteParser;
use tls13tutorial::tls_record::{ContentType, TLSInnerPlaintext, TLSRecord};

// Cryptographic libraries
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use rasn::types::UtcTime;
use rasn_pkix::{Name, Time, Validity};

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;

type HmacSha256 = Hmac<Sha256>;

const DEBUGGING_EPHEMERAL_SECRET: [u8; 32] = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Key calculation and resulting keys, includes initial random values for `ClientHello`
/// Check section about [KeySchedule](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
/// TODO: Separate Handshake and Application keys
struct HandshakeKeys {
    random_seed: Random,
    session_id: Random,
    // WARNING: we should use single-use `EphemeralSecret` for security in real systems
    dh_client_ephemeral_secret: StaticSecret,
    dh_client_public: PublicKey,
    dh_server_public: PublicKey,
    dh_shared_secret: Option<SharedSecret>, // Instanced later
    client_hs_key: Vec<u8>,
    client_hs_iv: Vec<u8>,
    client_hs_finished_key: Vec<u8>,
    client_seq_num: u64,
    server_hs_key: Vec<u8>,
    server_hs_iv: Vec<u8>,
    server_hs_finished_key: Vec<u8>,
    server_seq_num: u64,
    client_ap_key: Vec<u8>,
    client_ap_iv: Vec<u8>,
    server_ap_key: Vec<u8>,
    server_ap_iv: Vec<u8>,
}

impl HandshakeKeys {
    #[must_use]
    fn new() -> Self {
        // Generate 32 bytes of random data as key length is 32 bytes in SHA-256
        //let random_seed = rand::random::<[u8; 32]>();
        // FIXME use random data instead of hardcoded seed
        // Hardcoded value has been used for debugging purposes
        let random_seed = DEBUGGING_EPHEMERAL_SECRET;
        //let session_id = rand::random::<[u8; 32]>();
        let session_id = random_seed;
        // Generate a new Elliptic Curve Diffie-Hellman public-private key pair (X25519)
        let (dh_client_ephemeral_secret, dh_client_public);
        #[cfg(not(debug_assertions))]
        {
            dh_client_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
            dh_client_public = PublicKey::from(&dh_client_ephemeral_secret);
        }
        #[cfg(debug_assertions)]
        {
            dh_client_ephemeral_secret = StaticSecret::from(DEBUGGING_EPHEMERAL_SECRET);
            dh_client_public = PublicKey::from(&dh_client_ephemeral_secret);
        }

        Self {
            random_seed,
            session_id,
            dh_client_ephemeral_secret,
            dh_client_public,
            dh_server_public: PublicKey::from([0u8; 32]),
            dh_shared_secret: None,
            client_hs_key: vec![0u8; 32],
            client_hs_iv: vec![0u8; 12],
            client_hs_finished_key: vec![0u8; 32],
            client_seq_num: 0,
            server_hs_key: vec![0u8; 32],
            server_hs_iv: vec![0u8; 12],
            server_hs_finished_key: vec![0u8; 32],
            server_seq_num: 0,
            client_ap_key: vec![0u8; 32],
            client_ap_iv: vec![0u8; 32],
            server_ap_key: vec![0u8; 32],
            server_ap_iv: vec![0u8; 32],
        }
    }

    /// Update the keys based on handshake messages
    /// Specific for SHA256 hash function
    /// See especially Section 7. in the standard
    /// This function works correctly for the initial key calculation, to finish the handshake
    /// you need to also other keys later on following the same idea.
    fn key_schedule(&mut self, transcript_hash: &[u8]) {
        // Calculate the shared secret
        self.dh_shared_secret = Some(
            self.dh_client_ephemeral_secret
                .diffie_hellman(&self.dh_server_public),
        );

        // Early secret - we don't implement PSK, so need to use empty arrays
        let (early_secret, _hk) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &[0u8; 32]);
        let sha256_empty = Sha256::digest([]);
        let derived_secret = Self::derive_secret(&early_secret, b"derived", &sha256_empty, 32);

        // Handshake secrets with Key & IV pairs
        let (handshake_secret, _hk) = Hkdf::<Sha256>::extract(
            Some(&derived_secret),
            self.dh_shared_secret.as_ref().unwrap().as_bytes(),
        );

        let client_hs_traffic_secret =
            Self::derive_secret(&handshake_secret, b"c hs traffic", transcript_hash, 32);
        self.client_hs_key = Self::derive_secret(&client_hs_traffic_secret, b"key", &[], 32);
        self.client_hs_iv = Self::derive_secret(&client_hs_traffic_secret, b"iv", &[], 12);
        self.client_hs_finished_key =
            Self::derive_secret(&client_hs_traffic_secret, b"finished", &[], 32);
        let server_hs_traffic_secret =
            Self::derive_secret(&handshake_secret, b"s hs traffic", transcript_hash, 32);
        self.server_hs_key = Self::derive_secret(&server_hs_traffic_secret, b"key", &[], 32);
        self.server_hs_iv = Self::derive_secret(&server_hs_traffic_secret, b"iv", &[], 12);
        self.server_hs_finished_key =
            Self::derive_secret(&server_hs_traffic_secret, b"finished", &[], 32);

        let sha256_empty2 = Sha256::digest([]);
        //derived_secret = HKDF-Expand-Label(key: handshake_secret, label: "derived", ctx: empty_hash, len: 48)
        let derived_secret2 =
            Self::derive_secret(&handshake_secret, b"derived", &sha256_empty2, 32);
        //master_secret = HKDF-Extract(salt: derived_secret, key: 00...)
        let (master_secret, _hk) = Hkdf::<Sha256>::extract(Some(&derived_secret2), &[0u8; 32]);
        //client_secret = HKDF-Expand-Label(master_secret, b"c ap traffic", transcript_hash, 32)
        let client_ap_secret =
            Self::derive_secret(&master_secret, b"c ap traffic", transcript_hash, 32);
        //client_application_key = HKDF-Expand-Label(client_secret, b"key", &[], 32)
        self.client_ap_key = Self::derive_secret(&client_ap_secret, b"key", &[], 32);
        //client_application_iv = HKDF-Expand-Label(client_secret, b"iv", &[], 12)
        self.client_ap_iv = Self::derive_secret(&client_ap_secret, b"iv", &[], 12);
        //server_secret = HKDF-Expand-Label(master_secret, b"s ap traffic", transcript_hash, 32)
        let server_ap_secret =
            Self::derive_secret(&master_secret, b"s ap traffic", transcript_hash, 32);
        //server_application_key = HKDF-Expand-Label(server_secret, b"key", &[], 32)
        self.server_ap_key = Self::derive_secret(&server_ap_secret, b"key", &[], 32);
        //server_application_iv = HKDF-Expand-Label(server_secret, b"iv", &[], 12)
        self.server_ap_iv = Self::derive_secret(&server_ap_secret, b"iv", &[], 12);

        // Print all the keys as hex strings
        debug!(
            "Shared secret: {}",
            to_hex(self.dh_shared_secret.as_ref().unwrap().as_bytes())
        );
        debug!("Early secret: {}", to_hex(&early_secret));
        debug!("Derived secret: {}", to_hex(&derived_secret));
        debug!("Handshake secret: {}", to_hex(&handshake_secret));
        debug!(
            "Client handshake traffic secret: {}",
            to_hex(&client_hs_traffic_secret)
        );
        debug!("Client handshake key: {}", to_hex(&self.client_hs_key));
        debug!("Client handshake IV: {}", to_hex(&self.client_hs_iv));
        debug!(
            "Client handshake finished key: {}",
            to_hex(&self.client_hs_finished_key)
        );
        debug!(
            "Server handshake traffic secret: {}",
            to_hex(&server_hs_traffic_secret)
        );
        debug!("Server handshake key: {}", to_hex(&self.server_hs_key));
        debug!("Server handshake IV: {}", to_hex(&self.server_hs_iv));
        debug!(
            "Server handshake finished key: {}",
            to_hex(&self.server_hs_finished_key)
        );
    }

    /// Expand the secret with the label and transcript hash (hash bytes of the combination of messages)
    /// Label format is described in the RFC 8446 section 7.1
    /// FIXME will panic on invalid lengths. Maybe someone notices this with a bit of fuzzing..
    #[must_use]
    fn derive_secret(
        secret: &[u8],
        label: &[u8],
        transcript_hash: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        // All the labels are ASCII strings, prepend with "tls13 "
        let mut combined_label = b"tls13 ".to_vec();
        combined_label.extend_from_slice(label);
        hkdf_label.extend_from_slice(&u8::try_from(combined_label.len()).unwrap().to_be_bytes());
        hkdf_label.extend_from_slice(&combined_label);
        hkdf_label.extend_from_slice(&u8::try_from(transcript_hash.len()).unwrap().to_be_bytes());
        hkdf_label.extend_from_slice(transcript_hash);
        let hk = Hkdf::<Sha256>::from_prk(secret).expect("Failed to create HKDF from PRK");
        let mut okm = vec![0u8; length];
        hk.expand(&hkdf_label, &mut okm)
            .expect("Failed to expand the secret");
        okm
    }
}

/// Process the data from TCP stream in the chunks of 4096 bytes and
/// read the response data into a buffer in a form of Queue for easier parsing.
fn process_tcp_stream(mut stream: &mut TcpStream) -> io::Result<VecDeque<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut reader = io::BufReader::new(&mut stream);
    let mut buffer: VecDeque<u8> = VecDeque::new();
    let mut chunk = [0; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break, // End of data
            Ok(n) => {
                debug!("Received {n} bytes of data.");
                buffer.extend(&chunk[..n]);
            }
            // Nothing to read and no null termination
            // We don't wait more than 0.5 seconds
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                warn!("TCP read blocking for more than 0.5 seconds...force return.");
                return Ok(buffer);
            }
            Err(e) => {
                error!("Error when reading from the TCP stream: {}", e);
                return Err(e);
            }
        }
    }
    Ok(buffer)
}

/// Write TLSRecord to TCP stream
fn write_tcp_stream(stream: &mut TcpStream, record: &TLSRecord) {
    match stream.write_all(
        &record
            .as_bytes()
            .expect("Failed to serialize TLS Record into bytes"),
    ) {
        Ok(()) => {
            info!("The {:?} request has been sent...", record.record_type);
        }
        Err(e) => {
            error!("Failed to send the request: {e}");
        }
    }
}

// Read TLSRecords from TCP stream
fn read_tcp_stream(stream: &mut TcpStream) -> io::Result<Vec<TLSRecord>> {
    // Read all the response data into a `VecDeque` buffer
    let buffer = process_tcp_stream(stream).unwrap_or_else(|e| {
        error!("Failed to read the TCP response: {e}");
        std::process::exit(1)
    });

    let response_records = tls13tutorial::get_records(buffer).unwrap_or_else(|e| {
        error!("Failed to process the records: {e}");
        std::process::exit(1)
    });

    Ok(response_records)
}

// Create payload aad to be included in the encryption payload from TLSInnerPlaintext record bytes
fn create_encryption_aad(record_bytes: &Vec<u8>, encryption_padding: usize) -> io::Result<Vec<u8>> {
    let mut aad = Vec::new();
    aad.push(ContentType::ApplicationData as u8);
    aad.extend_from_slice(&TLS_VERSION_COMPATIBILITY.to_be_bytes());
    // Encrypting adds x bytes to the size. In our case that x = 16
    aad.extend_from_slice(
        &u16::try_from(record_bytes.len() + encryption_padding)
            .unwrap()
            .to_be_bytes(),
    );
    Ok(aad)
}

// Create payload aad to be included in the decryption payload from TLSRecord bytes
fn create_decryption_aad(record: &TLSRecord) -> io::Result<Vec<u8>> {
    let mut aad = Vec::new();
    aad.push(record.record_type as u8);
    aad.extend_from_slice(&record.legacy_record_version.to_be_bytes());
    aad.extend_from_slice(&record.length.to_be_bytes());

    Ok(aad)
}

// Create nonce for ChaChaPoly1305 encryption/decryption
fn create_nonce(sequence_number: u64, iv: &Vec<u8>) -> io::Result<Nonce> {
    // NOTE: Stupid alert
    let mut init_vec = vec![0u8; 4];
    init_vec.splice(4.., sequence_number.to_be_bytes().to_vec());

    // XOR iv and server_hs_iv to create decrytpion nonce
    let nonce: Vec<u8> = init_vec
        .iter()
        .zip(iv.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    Ok(*Nonce::from_slice(&nonce))
}

// Decrypt TSLRecord with ChaCha20Poly1305
fn decrypt_record(
    handshake_keys: &mut HandshakeKeys,
    record: &TLSRecord,
    is_hs: bool,
) -> io::Result<Vec<u8>> {
    // Create additional associated data for decryption
    let aad = create_decryption_aad(&record).unwrap();

    let payload = Payload {
        msg: &record.fragment,
        aad: &aad,
    };

    let iv: &Vec<u8>;
    let key: &Vec<u8>;

    if is_hs {
        iv = &handshake_keys.server_hs_iv;
        key = &handshake_keys.server_hs_key;
    } else {
        iv = &handshake_keys.server_ap_iv;
        key = &handshake_keys.server_ap_key;
    }

    let nonce = create_nonce(handshake_keys.server_seq_num, iv).unwrap();

    // Decryption cipher
    let cipher = ChaCha20Poly1305::new_from_slice(key);

    // Decrypt record
    let result = cipher.unwrap().decrypt(&nonce, payload).unwrap();

    // Update sequence counter
    handshake_keys.server_seq_num += 1;

    Ok(result)
}

// Encrypt TSLInnerPlaintext record bytes with ChaCha20Poly1305
fn encrypt_record(
    handshake_keys: &mut HandshakeKeys,
    record_bytes: &Vec<u8>,
    is_hs: bool,
) -> io::Result<Vec<u8>> {
    // Create additional associated data for encryption
    let aad = create_encryption_aad(&record_bytes, 16).unwrap();

    let payload = Payload {
        msg: &record_bytes,
        aad: &aad,
    };

    let iv: &Vec<u8>;
    let key: &Vec<u8>;

    if is_hs {
        iv = &handshake_keys.client_hs_iv;
        key = &handshake_keys.client_hs_key;
    } else {
        iv = &handshake_keys.client_ap_iv;
        key = &handshake_keys.client_ap_key;
    }

    let nonce = create_nonce(handshake_keys.client_seq_num, iv).unwrap();

    // Encryption cipher
    let cipher = ChaCha20Poly1305::new_from_slice(key);

    // Encrypt record
    let result = cipher.unwrap().encrypt(&nonce, payload).unwrap();

    // Update sequence counter
    handshake_keys.client_seq_num += 1;

    Ok(result)
}

// Check certificate expiration
fn check_certificate_expiration(validity: Validity) -> bool {
    // NOTE: Didn't bother to ask permission to use chrono
    let current_time = Time::Utc(UtcTime::from_timestamp_nanos(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64,
    ));

    let range = validity.not_before..validity.not_after;

    // Check validity
    if !range.contains(&current_time) {
        // TODO: Terminate with alert "certificate_expired"
        debug!("Sanity check: Certificate expired");
        debug!("{:?}", range);
        debug!("{:?}", current_time);
        return false;
    }

    true
}

// Check certificate CN(Common Name) matches hostname
fn check_certificate_cn(subject: Name, hostname: &str) -> bool {
    let mut correct_cn = false;
    // NOTE: No easy way to access, that I know of, so we have to be "hacky"
    // Subject consist of RelativeDistinguishName Type and Value pairs
    // Loop through RDNs and access type-value pairs with pop_first()
    // We know that values are text so turn the value into a string
    // TODO: Figure out ObjectIdentifier to access value directly
    match subject {
        rasn_pkix::Name::RdnSequence(rdn_sequence) => {
            'outer: for mut rdn in rdn_sequence {
                while !rdn.is_empty() {
                    let atav = rdn.pop_first().unwrap();
                    let value_bytes = atav.value.into_bytes();
                    // Ignore first 2 bytes, they don't contain anything valuable
                    let value_str =
                        str::from_utf8(&&value_bytes[2..]).expect("Failed to parse value into str");
                    if value_str == hostname {
                        correct_cn = true;
                        break 'outer;
                    }
                }
            }
        }
    }

    // If hostname was not found from subject, we cannot verify that Certificate belongs to host
    if !correct_cn {
        // TODO: Terminate with alert "certificate_unknown"
        debug!("Sanity check: Cannot verify Certificate belongs to the host");
        return false;
    }

    true
}

// Check certificate is valid (CN matching, Expiration check)
fn validate_certificate(certificate_data: &[u8], hostname: &str) {
    // TODO: Terminate if empty certificate with "decode_error"
    // Parse certificate
    let certificate = rasn::der::decode::<rasn_pkix::Certificate>(certificate_data)
        .expect("Failed to parse Certificate");

    // Get validity data
    let validity = certificate.tbs_certificate.validity;

    let not_expired = check_certificate_expiration(validity);

    if !not_expired {
        // TODO: Terminate with alert "certificate_expired"
    }

    // Need to get CN from subject
    let subject = certificate.tbs_certificate.subject;

    let correct_cn = check_certificate_cn(subject, hostname);

    if !correct_cn {
        // TODO: Terminate with alert "certificate_unknown"
    }

    // TODO: Check Certificate chain
    // NOTE: Too difficult to implement currently

    // TODO: Check if Certificate is revoked
    // NOTE: Too difficult to implemenet currently
}

// Verify certificate with EcdsaSecp256r1Sha256 signature
fn verify_certificate(certificate_data: &[u8], transcript_hash: &[u8], cert_signature: &[u8]) {
    // Parse certificate
    let certificate = rasn::der::decode::<rasn_pkix::Certificate>(&certificate_data)
        .expect("Failed to parse Certificate");

    // Extract certificate public key
    let mut cert_public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key;

    let mut pkey: Vec<u8> = Vec::new();

    cert_public_key
        .read_to_end(&mut pkey)
        .expect("Failed to read Certificate public key");

    // Create the message server signed to produce the signature
    let mut message = vec![0x20; 64];
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    message.push(0x00);
    message.extend_from_slice(&transcript_hash);

    // Load public key as EncodedPoint and use it initalize VerifyingKey
    let enc_point = EncodedPoint::from_bytes(&pkey)
        .expect("Failed to parse EncodedPoint from Certificate public key");
    let ver_key = VerifyingKey::from_encoded_point(&enc_point)
        .expect("Failed to parse VerifyingKey from Certificate public key");
    let signature = Signature::from_der(&cert_signature)
        .expect("Failed to parse Signature from CertificateVerify signature");

    // Verify certificate
    let result = ver_key.verify(&message, &signature);
    if result.is_err() {
        // TODO: Terminate with alert "bad_certificate"
        debug!("Sanity check: Certificate couldn't be verified");
    }
}

// Calculate verify_data for client Handshake Finished message
fn calculate_verify_data(
    handshake_keys: &mut HandshakeKeys,
    transcript_hash: &[u8],
) -> io::Result<Vec<u8>> {
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(&handshake_keys.client_hs_finished_key)
        .expect("Failed to initiate HMAC with key");
    hmac.update(&transcript_hash);
    let result = hmac.finalize();

    Ok(result.into_bytes().to_vec())
}

// Validate verify_data in server Handshake Finished message
fn validate_verify_data(
    handshake_keys: &mut HandshakeKeys,
    transcript_hash: &[u8],
    verify_data: Vec<u8>,
) -> Result<(), MacError> {
    // Create SHA256 HMAC
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(&handshake_keys.server_hs_finished_key)
        .expect("Failed to initiate HMAC with key");

    hmac.update(&transcript_hash);

    hmac.verify_slice(&verify_data)
}

/// Main event loop for the TLS 1.3 client implementation
#[allow(clippy::too_many_lines)]
fn main() {
    // Get address as command-line argument, e.g. cargo run cloudflare.com:443
    let args = std::env::args().collect::<Vec<String>>();
    let address = if args.len() > 1 {
        args[1].as_str()
    } else {
        eprintln!("Usage: {} <address:port>", args[0]);
        std::process::exit(1);
    };

    // Creating logger.
    // You can change the level with RUST_LOG environment variable, e.g. RUST_LOG=debug
    env_logger::builder().format_timestamp(None).init();
    // Note: unsafe, not  everything-covering validation for the address
    let Some((hostname, _port)) = address.split_once(':') else {
        error!("Invalid address:port format");
        std::process::exit(1);
    };

    // Create initial random values and keys for the handshake
    let mut handshake_keys = HandshakeKeys::new();

    // Create SHA256 hasher for Transcript-Hash
    // Have to use this "hack" because of a rust analyzer bug
    // r-a assumes the wrong new() and throws false positive: expected 1 argument, found 0 rust-analyzer(E0107)
    let mut sha256 = Sha256::new_with_prefix([]);

    match TcpStream::connect(address) {
        Ok(mut stream) => {
            info!("Successfully connected to the server '{address}'.");

            ////////////////////////////
            // This sends ClientHello //
            ////////////////////////////

            // Generate the ClientHello message with the help of the data structures
            // Selects the cipher suite and properties
            let client_hello = ClientHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: handshake_keys.random_seed,
                legacy_session_id: handshake_keys.session_id.into(),
                cipher_suites: vec![cipher_suites::TLS_CHACHA20_POLY1305_SHA256],
                legacy_compression_methods: vec![0],
                extensions: vec![
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SupportedVersions,
                        extension_data: ExtensionData::SupportedVersions(SupportedVersions {
                            version: VersionKind::Suggested(vec![TLS_VERSION_1_3]),
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::ServerName,
                        extension_data: ExtensionData::ServerName(ServerNameList {
                            server_name_list: vec![ServerName {
                                name_type: NameType::HostName,
                                host_name: hostname.to_string().as_bytes().to_vec(),
                            }],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SupportedGroups,
                        extension_data: ExtensionData::SupportedGroups(NamedGroupList {
                            named_group_list: vec![NamedGroup::X25519],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SignatureAlgorithms,
                        extension_data: ExtensionData::SignatureAlgorithms(
                            SupportedSignatureAlgorithms {
                                supported_signature_algorithms: vec![
                                    SignatureScheme::EcdsaSecp256r1Sha256,
                                ],
                            },
                        ),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::KeyShare,
                        extension_data: ExtensionData::KeyShareClientHello(KeyShareClientHello {
                            client_shares: vec![KeyShareEntry {
                                group: NamedGroup::X25519,
                                key_exchange: handshake_keys.dh_client_public.to_bytes().to_vec(),
                            }],
                        }),
                    },
                ],
            };

            info!("Sending ClientHello as follows...\n");
            println!("{client_hello}");
            // Alternative styles
            // dbg!(&client_hello);
            // println!("{client_hello:#?}");

            let handshake = Handshake {
                msg_type: HandshakeType::ClientHello,
                length: u32::try_from(
                    client_hello
                        .as_bytes()
                        .expect("Failed to serialize ClientHello message into bytes")
                        .len(),
                )
                .expect("ClientHello message too long"),
                message: HandshakeMessage::ClientHello(client_hello.clone()),
            };

            let client_handshake_bytes = handshake
                .as_bytes()
                .expect("Failed to serialize Handshake message into bytes");

            // Add handshake message to hasher
            sha256.update(client_handshake_bytes.clone());

            let request_record = TLSRecord {
                record_type: ContentType::Handshake,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: u16::try_from(client_handshake_bytes.len())
                    .expect("Handshake message too long"),
                fragment: client_handshake_bytes.clone(),
            };

            // Send the constructed request to the server
            write_tcp_stream(&mut stream, &request_record);

            // Read all the response data into a `VecDeque` buffer
            let response_records = read_tcp_stream(&mut stream);

            //////////////////////////////////////////////////////////////////////////////////////////////
            // This receives ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished //
            //////////////////////////////////////////////////////////////////////////////////////////////

            for record in response_records.unwrap() {
                match record.record_type {
                    ContentType::Alert => match Alert::from_bytes(&mut record.fragment.into()) {
                        Ok(alert) => {
                            warn!("Alert received: {alert}");
                        }
                        Err(e) => {
                            error!("Failed to parse the alert: {e}");
                        }
                    },
                    ContentType::Handshake => {
                        debug!("Raw handshake data: {:?}", record.fragment);
                        let hs_bytes = record.fragment.clone();
                        let handshake = *Handshake::from_bytes(&mut record.fragment.into())
                            .expect("Failed to parse Handshake message");
                        debug!("Handshake message: {:?}", &handshake);
                        if let HandshakeMessage::ServerHello(server_hello) = handshake.message {
                            info!("ServerHello message: {:?}", server_hello);
                            // TODO: Check random for HelloRetryRequest bytes
                            // TODO: Check random last 8 bytes for TLS 1.2 or 1.1 or below negoation bytes,
                            // MUST throw illegal parameter alert
                            for extension in server_hello.extensions {
                                match extension.extension_data {
                                    ExtensionData::KeyShareServerHello(key_share_server_hello) => {
                                        // TODO: Check that group is correct
                                        // TODO: length check or error handling
                                        let server_public_key: [u8; 32] = key_share_server_hello
                                            .server_share
                                            .key_exchange
                                            .try_into()
                                            .unwrap();

                                        // Server public key
                                        handshake_keys.dh_server_public =
                                            PublicKey::from(server_public_key);

                                        // Add handshake message to hasher
                                        sha256.update(&hs_bytes);

                                        // Get updated hash
                                        let transcript_hash = sha256.clone().finalize();
                                        debug!("Hash: {}", to_hex(&transcript_hash));

                                        // Update keys
                                        handshake_keys.key_schedule(&transcript_hash)
                                    }
                                    ExtensionData::SupportedVersions(_supported_version) => {}
                                    _ => {
                                        //TODO: Add rest of the allowed extension in ServerHello
                                        error!("Unexpected extension in ServerHello");
                                    }
                                }
                            }
                        }
                    }
                    ContentType::ApplicationData => {
                        // Application data received
                        // Decrypt the data using the keys
                        // Read TLSInnerPlaintext and proceed with the handshake
                        info!("Application data received, size of : {:?}", record.length);
                        assert_eq!(record.fragment.len(), record.length as usize);

                        // Decrypt TLSRecord
                        let result = decrypt_record(&mut handshake_keys, &record, true).unwrap();

                        let plaintext = *TLSInnerPlaintext::from_bytes(&mut result.clone().into())
                            .expect("Failed to parse TLSInnerPlaintext");
                        debug!("TLSInnerPlaintext content data: {:?}", plaintext.content);
                        debug!(
                            "TLSInnerPlaintext content length: {:?}",
                            plaintext.content.len()
                        );

                        // TLSInnerPlaintext can be encoded Handshake or Alert message
                        match plaintext.content_type {
                            ContentType::Handshake => {
                                // Note TLSInnerPlaintext can contain multiple messages
                                // plaintext.content should not have any extra bytes
                                let mut content_bytes = ByteParser::from(plaintext.content);
                                let mut cert_data = Vec::new();

                                while !content_bytes.is_empty() {
                                    let handshake = *Handshake::from_bytes(&mut content_bytes)
                                        .expect("Failed to parse Handshake message");
                                    debug!("Handshake message: {:?}", &handshake);

                                    // Check that Finished verify_data matches
                                    match handshake.clone().message {
                                        HandshakeMessage::Certificate(certificate) => {
                                            // TODO: Terminate if empty certificate with "decode_error"
                                            // NOTE: We only want the first certificate for now
                                            let cert_copy = certificate.clone();
                                            let cert_entry =
                                                cert_copy.certificate_list.first().unwrap();
                                            cert_data
                                                .extend_from_slice(&cert_entry.certificate_data);

                                            // Validate certificate
                                            validate_certificate(
                                                &cert_entry.certificate_data,
                                                hostname,
                                            );
                                        }
                                        HandshakeMessage::CertificateVerify(certificate_verify) => {
                                            debug!("Verify this cert data: {:?}", cert_data);
                                            let transcript_hash = sha256.clone().finalize();

                                            // Verify certificate
                                            verify_certificate(
                                                &cert_data,
                                                &transcript_hash,
                                                &certificate_verify.signature,
                                            )
                                        }
                                        HandshakeMessage::Finished(finished) => {
                                            let transcript_hash = sha256.clone().finalize();

                                            let _result = validate_verify_data(
                                                &mut handshake_keys,
                                                &transcript_hash,
                                                finished.verify_data.clone(),
                                            )
                                            .map_err(|_| {
                                                // TODO: Terminate with "decrypt_error"
                                                std::io::Error::new(
                                                    std::io::ErrorKind::InvalidData,
                                                    "Invalid Server Finished verify_data",
                                                )
                                            });
                                        }
                                        _ => {
                                            // TODO: Add something here? :D
                                        }
                                    }

                                    // Add handshake messages to hasher
                                    sha256.update(
                                        handshake
                                            .as_bytes()
                                            .expect("Failed to parse Handshake message"),
                                    );
                                    debug!("Handshake message bytes: {:?}", &handshake.message);
                                    debug!("Added {:?} message to hasher", &handshake.msg_type);
                                }
                            }
                            ContentType::Alert => {
                                let mut content_bytes = ByteParser::from(plaintext.content);
                                let alert = *Alert::from_bytes(&mut content_bytes)
                                    .expect("Failed to parse Alert message");
                                debug!("Alert message: {:?}", &alert);
                            }
                            _ => {
                                error!("Unexpected response type: {:?}", record.record_type);
                                // debug!("Remaining bytes: {:?}", parser.deque);
                            }
                        }
                    }
                    _ => {
                        error!("Unexpected response type: {:?}", record.record_type);
                        // debug!("Remaining bytes: {:?}", parser.deque);
                    }
                }
            }

            // Not needed but just for the fun of it
            // Copied from OpenSSL message log
            // TODO: Create a proper message type in tls_record.rs
            let change_cipher_spec_record = TLSRecord {
                record_type: ContentType::ChangeCipherSpec,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: 1,
                fragment: vec![1],
            };

            // Send the constructed request to the server
            write_tcp_stream(&mut stream, &change_cipher_spec_record);

            /////////////////////////
            // This sends Finished //
            /////////////////////////

            // CertificateVerify is already added to hasher
            let transcript_hash = sha256.clone().finalize();

            // Calculate verify_data
            let verify_data = calculate_verify_data(&mut handshake_keys, &transcript_hash).unwrap();

            // Create Client Finished message
            let client_finished = Finished { verify_data };

            // Create Handshake message for Client Finished
            let handshake = Handshake {
                msg_type: HandshakeType::Finished,
                length: u32::try_from(
                    client_finished
                        .as_bytes()
                        .expect("Failed to serialize Finished message into bytes")
                        .len(),
                )
                .expect("Finished message too long"),
                message: HandshakeMessage::Finished(client_finished.clone()),
            };

            // Get Handshake bytes
            let finished_handshake_bytes = handshake
                .as_bytes()
                .expect("Failed to serialize Handshake message into bytes");

            // Create TLSInnerPlaintext for Handshake message
            let plaintext = TLSInnerPlaintext {
                content: finished_handshake_bytes,
                content_type: ContentType::Handshake,
                zeros: Vec::new(),
            };

            // Get Plaintext bytes
            let plaintext_bytes = plaintext
                .as_bytes()
                .expect("Failed to serialize TLSInnerPlaintext into bytes");

            // Encrypt TLSInnerPlaintext
            let result = encrypt_record(&mut handshake_keys, &plaintext_bytes, true).unwrap();

            // Create TLSRecord for Encrypted message
            let request_record = TLSRecord {
                record_type: ContentType::ApplicationData,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: u16::try_from(result.len()).expect("Encrypted message too long"),
                fragment: result.clone(),
            };

            // Send the constructed request to the server
            write_tcp_stream(&mut stream, &request_record);

            // Reset sequence numbers and calculate application keys
            handshake_keys.server_seq_num = 0;
            handshake_keys.client_seq_num = 0;
            handshake_keys.key_schedule(&sha256.clone().finalize());

            /////////////////////////////////
            // This sends Application Data //
            /////////////////////////////////

            let application_data =
                b"GET /robots.txt HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n"
                    .to_vec();

            // Create TLSInnerPlaintext for Handshake message
            let plaintext = TLSInnerPlaintext {
                content: application_data,
                content_type: ContentType::ApplicationData,
                zeros: Vec::new(),
            };

            // Get Plaintext bytes
            let plaintext_bytes = plaintext
                .as_bytes()
                .expect("Failed to serialize TLSInnerPlaintext into bytes");

            // Encrypt TLSInnerPlaintext
            let result = encrypt_record(&mut handshake_keys, &plaintext_bytes, false).unwrap();

            // Create TLSRecord for Encrypted message
            let request_record = TLSRecord {
                record_type: ContentType::ApplicationData,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: u16::try_from(result.len()).expect("Encrypted message too long"),
                fragment: result.clone(),
            };

            // Send the constructed request to the server
            write_tcp_stream(&mut stream, &request_record);

            //////////////////////////////////////////////
            // This reads response to  Application Data //
            //////////////////////////////////////////////

            // Read all the response data into a `VecDeque` buffer
            let response_records = read_tcp_stream(&mut stream);

            for record in response_records.unwrap() {
                // No need to match, everything should be ApplicationData
                let result = decrypt_record(&mut handshake_keys, &record, false).unwrap();

                let plaintext = *TLSInnerPlaintext::from_bytes(&mut result.clone().into())
                    .expect("Failed to parse TLSInnerPlaintext");
                debug!("TLSInnerPlaintext content data: {:?}", plaintext.content);
                debug!(
                    "TLSInnerPlaintext content length: {:?}",
                    plaintext.content.len()
                );

                // TLSInnerPlaintext can be encoded ApplicationData or Alert message
                match plaintext.content_type {
                    ContentType::Alert => match Alert::from_bytes(&mut plaintext.content.into()) {
                        Ok(alert) => {
                            warn!("Alert received: {alert}");
                            // TODO: Check if CloseNotify and send it back and close
                        }
                        Err(e) => {
                            error!("Failed to parse the alert: {e}");
                        }
                    },
                    _ => {
                        // TODO: later
                        debug!("Handle other than Alert records");
                        info!("Received record: {:?}", plaintext.content_type);
                        info!(
                            "Record content: {:?}",
                            str::from_utf8(&plaintext.content).unwrap()
                        );
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to connect: {e}");
        }
    }
}
