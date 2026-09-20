// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Core pure-memory DNS packet dispatcher (zero-I/O pipeline)
pub fn handle_dns_packet(
  zone : @zone.Zone,
  request_bytes : Bytes,
  is_tcp : Bool
) -> Result[Bytes, @types.DnsError] {
  let query = match @codec.decode_message(request_bytes) {
    Ok(msg) => msg
    Err(e) => return Err(e)
  }

  // Determine maximum response size allowed by protocol and client
  let max_size = if is_tcp {
    65535 // TCP allows up to 64KB
  } else {
    match @resolver.find_opt_record(query) {
      Some(opt) => {
        let sz = opt.udp_payload_size.to_int()
        if sz < 512 { 512 } else { sz }
      }
      None => 512 // Standard RFC 1035 UDP limit without EDNS0
    }
  }

  // Build authoritative response
  let resp = @resolver.build_response(query, zone)

  // Truncate response if exceeding allowed buffer size
  let output_bytes = @resolver.truncate_response(resp, max_size)
  Ok(output_bytes)
}

///| Pack a DNS message with a 2-byte big-endian length prefix for TCP transmission (RFC 1035 Section 4.2.2)
pub fn encode_tcp_frame(message_bytes : Bytes) -> Bytes {
  let writer = @bytes_io.ByteWriter::new()
  writer.write_uint16(message_bytes.length().to_uint16())
  writer.write_bytes(message_bytes)
  writer.to_bytes()
}

///| Unpack a 2-byte length-prefixed DNS message from a TCP stream
pub fn decode_tcp_frame(
  reader : @bytes_io.ByteReader
) -> Result[Bytes, @types.DnsError] {
  let length_prefix = match reader.read_uint16() {
    Ok(l) => l.to_int()
    Err(e) => return Err(e)
  }
  reader.read_bytes(length_prefix)
}

///| High-level Server Dispatcher representing an Authoritative DNS Server instance
pub(all) struct DnsServer {
  zone : @zone.Zone
  mut query_count : UInt64
  mut error_count : UInt64
} derive(Debug)

///| Create a new DnsServer for a given Zone database
pub fn DnsServer::new(zone : @zone.Zone) -> DnsServer {
  {
    zone,
    query_count: 0,
    error_count: 0,
  }
}

///| Process an incoming raw UDP datagram and return response bytes (or Err)
pub fn DnsServer::process_udp(
  self : DnsServer,
  raw_request : Bytes
) -> Result[Bytes, @types.DnsError] {
  self.query_count = self.query_count + 1
  match handle_dns_packet(self.zone, raw_request, false) {
    Ok(bytes) => Ok(bytes)
    Err(e) => {
      self.error_count = self.error_count + 1
      Err(e)
    }
  }
}

///| Process an incoming raw TCP stream payload and return 2-byte prefixed response bytes
pub fn DnsServer::process_tcp(
  self : DnsServer,
  raw_tcp_frame : Bytes
) -> Result[Bytes, @types.DnsError] {
  self.query_count = self.query_count + 1
  let reader = @bytes_io.ByteReader::new(raw_tcp_frame)
  let payload = match decode_tcp_frame(reader) {
    Ok(p) => p
    Err(e) => {
      self.error_count = self.error_count + 1
      return Err(e)
    }
  }

  match handle_dns_packet(self.zone, payload, true) {
    Ok(resp_bytes) => Ok(encode_tcp_frame(resp_bytes))
    Err(e) => {
      self.error_count = self.error_count + 1
      Err(e)
    }
  }
}
