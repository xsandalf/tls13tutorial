#![no_main]

use libfuzzer_sys::fuzz_target;
use tls13tutorial::extensions::ByteSerializable;
use tls13tutorial::fuzz_round_trip; // See macros.rs to fuzz any type as alert below
use tls13tutorial::parser::ByteParser;
use tls13tutorial::tls_record::{TLSInnerPlaintext, TLSRecord};

fuzz_target!(|data: &[u8]| {
    // code to fuzz goes here
    fuzz_tls_record(data);
    fuzz_tls_inner_plaintext(data);
});

fn fuzz_tls_record(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(TLSRecord, data);
}

fn fuzz_tls_inner_plaintext(data: &[u8]) {
    // Macro takes type which implements ByteSerializable and the data to fuzz
    fuzz_round_trip!(TLSInnerPlaintext, data);
}
