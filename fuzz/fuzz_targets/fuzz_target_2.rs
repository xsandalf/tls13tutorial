#![no_main]

use libfuzzer_sys::fuzz_target;
use tls13tutorial::extensions::{
    ByteSerializable, Cookie, Extension, ExtensionOrigin, KeyShareClientHello, KeyShareEntry,
    KeyShareServerHello, NamedGroup, NamedGroupList, PskKeyExchangeModes, ServerNameList,
    SignatureScheme, SupportedSignatureAlgorithms, SupportedVersions,
};
use tls13tutorial::fuzz_round_trip; // See macros.rs to fuzz any type as alert below
use tls13tutorial::parser::ByteParser;

fuzz_target!(|data: &[u8]| {
    // code to fuzz goes here
    fuzz_extension(data);
    fuzz_server_name_list(data);
    fuzz_named_group(data);
    fuzz_named_group_list(data);
    fuzz_signature_scheme(data);
    fuzz_supported_signature_algorithms(data);
    fuzz_supported_versions(data);
    fuzz_key_share_entry(data);
    fuzz_key_share_client_hello(data);
    fuzz_key_share_server_hello(data);
    fuzz_psk_key_exchange_mode(data);
    fuzz_cookie(data);
});

fn fuzz_extension(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    //fuzz_round_trip!(Extension, data);
    let backup = data.to_vec();
    let mut parser = ByteParser::from(data);
    if let Ok(decoded_value) = Extension::from_bytes(&mut parser, ExtensionOrigin::Client) {
        if let Some(actual_encoding) = decoded_value.as_bytes() {
            assert_eq!(actual_encoding, backup);
        }
    }

    let backup = data.to_vec();
    let mut parser = ByteParser::from(data);
    if let Ok(decoded_value) = Extension::from_bytes(&mut parser, ExtensionOrigin::Server) {
        if let Some(actual_encoding) = decoded_value.as_bytes() {
            assert_eq!(actual_encoding, backup);
        }
    }
}

fn fuzz_server_name_list(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(ServerNameList, data);
}

fn fuzz_named_group(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(NamedGroup, data);
}

fn fuzz_named_group_list(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(NamedGroupList, data);
}

fn fuzz_signature_scheme(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(SignatureScheme, data);
}

fn fuzz_supported_signature_algorithms(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(SupportedSignatureAlgorithms, data);
}

fn fuzz_supported_versions(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(SupportedVersions, data);
}

fn fuzz_key_share_entry(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(KeyShareEntry, data);
}

fn fuzz_key_share_client_hello(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(KeyShareClientHello, data);
}

fn fuzz_key_share_server_hello(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(KeyShareServerHello, data);
}

fn fuzz_psk_key_exchange_mode(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(PskKeyExchangeModes, data);
}

fn fuzz_cookie(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(Cookie, data);
}
