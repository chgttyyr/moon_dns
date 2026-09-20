// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| DnsError represents all protocol, parsing, and serialization error variants.
pub(all) enum DnsError {
  BufferUnderflow(String)
  BufferOverflow(String)
  MalformedLabel(String)
  MalformedPointer(String)
  InvalidLength(String)
  InvalidCharacter(String)
  UnsupportedType(UInt16)
  ProtocolError(String)
  IoError(String)
} derive(Debug, Eq)

///| Returns a human-readable description of the DNS error.
pub fn DnsError::message(self : DnsError) -> String {
  match self {
    BufferUnderflow(msg) => "Buffer underflow: " + msg
    BufferOverflow(msg) => "Buffer overflow: " + msg
    MalformedLabel(msg) => "Malformed label: " + msg
    MalformedPointer(msg) => "Malformed or malicious pointer: " + msg
    InvalidLength(msg) => "Invalid length: " + msg
    InvalidCharacter(msg) => "Invalid character: " + msg
    UnsupportedType(code) => "Unsupported RR type: " + code.to_string()
    ProtocolError(msg) => "DNS protocol error: " + msg
    IoError(msg) => "I/O error: " + msg
  }
}
