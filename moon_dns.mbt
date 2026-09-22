// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| MoonDNS Release Version String
pub const VERSION : String = "0.1.0"

///| Public facade to create a fully initialized DnsServer from a BIND master-file zone text
pub fn create_server_from_zone_text(
  origin : String,
  zone_text : String
) -> Result[@transport.DnsServer, @types.DnsError] {
  let zone = match @zone.parse_zone_text(origin, zone_text) {
    Ok(z) => z
    Err(e) => return Err(e)
  }
  Ok(@transport.DnsServer::new(zone))
}

///| High-level helper to query an in-memory DnsServer directly and obtain answered records
pub fn quick_resolve(
  server : @transport.DnsServer,
  domain : String,
  rtype : @types.RType
) -> Result[Array[@types.Record], @types.DnsError] {
  let query = @types.Message::new_query(0x1337, domain, rtype)
  let raw_req = @codec.encode_message(query)
  let raw_resp = match server.process_udp(raw_req) {
    Ok(bytes) => bytes
    Err(e) => return Err(e)
  }
  let resp_msg = match @codec.decode_message(raw_resp) {
    Ok(msg) => msg
    Err(e) => return Err(e)
  }
  Ok(resp_msg.answers)
}

fn hex_nibble_to_char(n : Int) -> Char {
  if n < 10 {
    Int::unsafe_to_char(48 + n)
  } else {
    Int::unsafe_to_char(97 + n - 10)
  }
}

fn char_to_hex_nibble(c : Int) -> Int {
  if c >= 48 && c <= 57 {
    c - 48
  } else if c >= 97 && c <= 102 {
    c - 97 + 10
  } else if c >= 65 && c <= 70 {
    c - 65 + 10
  } else {
    0
  }
}

///| Helper to convert binary Bytes into a lowercase hexadecimal string
pub fn bytes_to_hex(bytes : Bytes) -> String {
  let buf = StringBuilder()
  for i = 0; i < bytes.length(); i = i + 1 {
    let b = bytes[i].to_int() & 0xFF
    let hi = (b >> 4) & 0x0F
    let lo = b & 0x0F
    buf.write_char(hex_nibble_to_char(hi))
    buf.write_char(hex_nibble_to_char(lo))
  }
  buf.to_string()
}

///| Helper to convert a hexadecimal string into binary Bytes
pub fn hex_to_bytes(hex : String) -> Bytes {
  let len = hex.length()
  let writer = @bytes_io.ByteWriter::new()
  let mut i = 0
  while i + 1 < len {
    let h1 = char_to_hex_nibble(hex[i].to_int())
    let h2 = char_to_hex_nibble(hex[i + 1].to_int())
    let b = (h1 << 4) | h2
    writer.write_byte(b.to_byte())
    i = i + 2
  }
  writer.to_bytes()
}

///| Direct raw DNS packet resolution over UDP pipeline
pub fn resolve_raw_packet(
  server : @transport.DnsServer,
  raw_req : Bytes
) -> Result[Bytes, @types.DnsError] {
  server.process_udp(raw_req)
}

///| WebAssembly/JS-friendly hex packet resolution: takes hex string, returns response hex string
pub fn resolve_hex_packet(
  server : @transport.DnsServer,
  hex_req : String
) -> Result[String, @types.DnsError] {
  let req_bytes = hex_to_bytes(hex_req)
  match server.process_udp(req_bytes) {
    Ok(resp_bytes) => Ok(bytes_to_hex(resp_bytes))
    Err(e) => Err(e)
  }
}
