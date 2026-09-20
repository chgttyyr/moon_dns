// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Parse a dotted-quad IPv4 string (e.g. "192.0.2.1") into RData::A
pub fn parse_ipv4(ip_str : String) -> Result[@types.RData, @types.DnsError] {
  let parts : Array[Int] = []
  let mut current = 0
  let mut has_digit = false
  let trimmed = ip_str.trim().to_owned()
  for i = 0; i < trimmed.length(); i = i + 1 {
    let ch = trimmed[i].to_int()
    if ch >= 48 && ch <= 57 {
      current = current * 10 + (ch - 48)
      if current > 255 {
        return Err(@types.InvalidCharacter("IPv4 octet exceeds 255: " + ip_str))
      }
      has_digit = true
    } else if ch == 46 { // '.'
      if !has_digit {
        return Err(@types.InvalidCharacter("Empty octet in IPv4: " + ip_str))
      }
      parts.push(current)
      current = 0
      has_digit = false
    } else {
      return Err(@types.InvalidCharacter("Invalid char in IPv4: " + ip_str))
    }
  }
  if !has_digit {
    return Err(@types.InvalidCharacter("Trailing dot or empty octet in IPv4: " + ip_str))
  }
  parts.push(current)
  if parts.length() != 4 {
    return Err(@types.InvalidLength("IPv4 must contain exactly 4 octets: " + ip_str))
  }
  Ok(@types.RData::A(
    parts[0].to_byte(),
    parts[1].to_byte(),
    parts[2].to_byte(),
    parts[3].to_byte()
  ))
}

///| Encode an A record RDATA into wire format (strictly 4 bytes)
pub fn encode_rdata_a(
  writer : @bytes_io.ByteWriter,
  b0 : Byte,
  b1 : Byte,
  b2 : Byte,
  b3 : Byte
) -> Unit {
  writer.write_byte(b0)
  writer.write_byte(b1)
  writer.write_byte(b2)
  writer.write_byte(b3)
}

///| Decode an A record RDATA from wire format (strictly 4 bytes)
pub fn decode_rdata_a(
  reader : @bytes_io.ByteReader,
  rdlength : UInt16
) -> Result[@types.RData, @types.DnsError] {
  if rdlength != 4 {
    return Err(@types.InvalidLength("A record RDLENGTH must be 4, got: " + rdlength.to_string()))
  }
  let b0 = match reader.read_byte() {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let b1 = match reader.read_byte() {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let b2 = match reader.read_byte() {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let b3 = match reader.read_byte() {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  Ok(@types.RData::A(b0, b1, b2, b3))
}

///| Encode an AAAA record RDATA into wire format (strictly 16 bytes)
pub fn encode_rdata_aaaa(
  writer : @bytes_io.ByteWriter,
  bytes : FixedArray[Byte]
) -> Result[Unit, @types.DnsError] {
  if bytes.length() != 16 {
    return Err(@types.InvalidLength("AAAA record payload must be 16 bytes"))
  }
  writer.write_fixed_bytes(bytes)
  Ok(())
}

///| Decode an AAAA record RDATA from wire format (strictly 16 bytes)
pub fn decode_rdata_aaaa(
  reader : @bytes_io.ByteReader,
  rdlength : UInt16
) -> Result[@types.RData, @types.DnsError] {
  if rdlength != 16 {
    return Err(@types.InvalidLength("AAAA record RDLENGTH must be 16, got: " + rdlength.to_string()))
  }
  let raw = match reader.read_bytes(16) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let arr = FixedArray::make(16, (0).to_byte())
  for i = 0; i < 16; i = i + 1 {
    arr[i] = raw[i]
  }
  Ok(@types.RData::AAAA(arr))
}

///| Encode a CNAME record RDATA into wire format (uncompressed domain)
pub fn encode_rdata_cname(
  writer : @bytes_io.ByteWriter,
  cname : String
) -> Result[Unit, @types.DnsError] {
  @domain.encode_domain_labels(writer, cname)
}

///| Decode a CNAME record RDATA from wire format
pub fn decode_rdata_cname(
  reader : @bytes_io.ByteReader
) -> Result[@types.RData, @types.DnsError] {
  let name = match @domain.decode_domain_labels(reader) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  Ok(@types.RData::CNAME(name))
}

///| Encode an NS record RDATA into wire format (uncompressed domain)
pub fn encode_rdata_ns(
  writer : @bytes_io.ByteWriter,
  nsdname : String
) -> Result[Unit, @types.DnsError] {
  @domain.encode_domain_labels(writer, nsdname)
}

///| Decode an NS record RDATA from wire format
pub fn decode_rdata_ns(
  reader : @bytes_io.ByteReader
) -> Result[@types.RData, @types.DnsError] {
  let name = match @domain.decode_domain_labels(reader) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  Ok(@types.RData::NS(name))
}
