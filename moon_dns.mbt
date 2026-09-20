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
