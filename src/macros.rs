// NO NEED TO MODIFY THIS FILE
//
// A macro for testing encoding/decoding for a generic type which implements ByteSerializable
// Takes a type and an object created from the type, an expected byte array for the encoding result
// Useful for testing both decoding and encoding
#[macro_export]
macro_rules! round_trip {
    ($typ:ty, $value:expr, $expected:expr) => {{
        let value: $typ = $value;
        let expected: &[u8] = $expected;
        let actual_encoding = $value.as_bytes().unwrap();
        pretty_assertions::assert_eq!(expected, &*actual_encoding);
        // Drop the remainder bytes in this case
        let mut actual_encoding = ByteParser::from(actual_encoding);
        let decoded_value = <$typ>::from_bytes(&mut actual_encoding).unwrap();
        pretty_assertions::assert_eq!(value, *decoded_value);
    }};
}
