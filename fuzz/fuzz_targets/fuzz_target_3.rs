#![no_main]

use libfuzzer_sys::fuzz_target;
use tls13tutorial::extensions::ByteSerializable;
use tls13tutorial::fuzz_round_trip; // See macros.rs to fuzz any type as alert below
use tls13tutorial::handshake::{
    Certificate, CertificateVerify, ClientHello, EncryptedExtensions, Finished, Handshake,
    ServerHello,
};
use tls13tutorial::parser::ByteParser;

fuzz_target!(|data: &[u8]| {
    // code to fuzz goes here
    fuzz_handshake(data);
    fuzz_client_hello(data);
    fuzz_server_hello(data);
    fuzz_encrypted_extensions(data);
    fuzz_certificate(data);
    fuzz_certificate_verify(data);
    fuzz_finished(data);
});

fn fuzz_handshake(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(Handshake, data);
}

fn fuzz_client_hello(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(ClientHello, data);
}

fn fuzz_server_hello(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(ServerHello, data);
}

fn fuzz_encrypted_extensions(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(EncryptedExtensions, data);
}

fn fuzz_certificate(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(Certificate, data);
}

fn fuzz_certificate_verify(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(CertificateVerify, data);
}

fn fuzz_finished(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(Finished, data);
}
