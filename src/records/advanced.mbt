// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Encode an MX record RDATA (2-byte preference + exchange domain)
pub fn encode_rdata_mx(
  writer : @bytes_io.ByteWriter,
  preference : UInt16,
  exchange : String
) -> Result[Unit, @types.DnsError] {
  writer.write_uint16(preference)
  @domain.encode_domain_labels(writer, exchange)
}

///| Decode an MX record RDATA from wire format
pub fn decode_rdata_mx(
  reader : @bytes_io.ByteReader
) -> Result[@types.RData, @types.DnsError] {
  let preference = match reader.read_uint16() {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let exchange = match @domain.decode_domain_labels(reader) {
    Ok(d) => d
    Err(e) => return Err(e)
  }
  Ok(@types.RData::MX(preference, exchange))
}

///| Encode a TXT record RDATA (one or more length-prefixed character-strings, RFC 1035)
pub fn encode_rdata_txt(
  writer : @bytes_io.ByteWriter,
  chunks : Array[String]
) -> Result[Unit, @types.DnsError] {
  if chunks.length() == 0 {
    // Empty TXT is represented as a single 0-length character-string
    writer.write_byte((0).to_byte())
    return Ok(())
  }
  for i = 0; i < chunks.length(); i = i + 1 {
    let chunk = chunks[i]
    let len = chunk.length()
    if len > 255 {
      return Err(@types.InvalidLength("TXT character-string exceeds 255 octets: " + len.to_string()))
    }
    writer.write_byte(len.to_byte())
    for j = 0; j < len; j = j + 1 {
      writer.write_byte(chunk[j].to_int().to_byte())
    }
  }
  Ok(())
}

///| Decode a TXT record RDATA from wire format using total rdlength
pub fn decode_rdata_txt(
  reader : @bytes_io.ByteReader,
  rdlength : UInt16
) -> Result[@types.RData, @types.DnsError] {
  let chunks : Array[String] = []
  let mut remaining = rdlength.to_int()
  if remaining == 0 {
    return Ok(@types.RData::TXT([]))
  }
  while remaining > 0 {
    let len_byte = match reader.read_byte() {
      Ok(b) => b
      Err(e) => return Err(e)
    }
    let chunk_len = len_byte.to_int()
    remaining = remaining - 1
    if chunk_len > remaining {
      return Err(@types.BufferUnderflow("TXT chunk length " + chunk_len.to_string() + " exceeds remaining RDATA " + remaining.to_string()))
    }
    let str_bytes = match reader.read_bytes(chunk_len) {
      Ok(bs) => bs
      Err(e) => return Err(e)
    }
    let buf = StringBuilder()
    for i = 0; i < chunk_len; i = i + 1 {
      buf.write_char(Int::unsafe_to_char(str_bytes[i].to_int()))
    }
    chunks.push(buf.to_string())
    remaining = remaining - chunk_len
  }
  Ok(@types.RData::TXT(chunks))
}

///| Encode an SOA record RDATA (RFC 1035 Section 3.3.13)
pub fn encode_rdata_soa(
  writer : @bytes_io.ByteWriter,
  mname : String,
  rname : String,
  serial : UInt,
  refresh : UInt,
  retry : UInt,
  expire : UInt,
  minimum : UInt
) -> Result[Unit, @types.DnsError] {
  let res1 = @domain.encode_domain_labels(writer, mname)
  match res1 {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  let res2 = @domain.encode_domain_labels(writer, rname)
  match res2 {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  writer.write_uint32(serial)
  writer.write_uint32(refresh)
  writer.write_uint32(retry)
  writer.write_uint32(expire)
  writer.write_uint32(minimum)
  Ok(())
}

///| Decode an SOA record RDATA from wire format
pub fn decode_rdata_soa(
  reader : @bytes_io.ByteReader
) -> Result[@types.RData, @types.DnsError] {
  let mname = match @domain.decode_domain_labels(reader) {
    Ok(m) => m
    Err(e) => return Err(e)
  }
  let rname = match @domain.decode_domain_labels(reader) {
    Ok(r) => r
    Err(e) => return Err(e)
  }
  let serial = match reader.read_uint32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let refresh = match reader.read_uint32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let retry = match reader.read_uint32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let expire = match reader.read_uint32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let minimum = match reader.read_uint32() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  Ok(@types.RData::SOA(mname, rname, serial, refresh, retry, expire, minimum))
}

///| Encode a PTR record RDATA (target domain)
pub fn encode_rdata_ptr(
  writer : @bytes_io.ByteWriter,
  ptrdname : String
) -> Result[Unit, @types.DnsError] {
  @domain.encode_domain_labels(writer, ptrdname)
}

///| Decode a PTR record RDATA from wire format
pub fn decode_rdata_ptr(
  reader : @bytes_io.ByteReader
) -> Result[@types.RData, @types.DnsError] {
  let name = match @domain.decode_domain_labels(reader) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  Ok(@types.RData::PTR(name))
}

///| Encode an SRV record RDATA (priority, weight, port, target, RFC 2782)
pub fn encode_rdata_srv(
  writer : @bytes_io.ByteWriter,
  priority : UInt16,
  weight : UInt16,
  port : UInt16,
  target : String
) -> Result[Unit, @types.DnsError] {
  writer.write_uint16(priority)
  writer.write_uint16(weight)
  writer.write_uint16(port)
  @domain.encode_domain_labels(writer, target)
}

///| Decode an SRV record RDATA from wire format
pub fn decode_rdata_srv(
  reader : @bytes_io.ByteReader
) -> Result[@types.RData, @types.DnsError] {
  let priority = match reader.read_uint16() {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let weight = match reader.read_uint16() {
    Ok(w) => w
    Err(e) => return Err(e)
  }
  let port = match reader.read_uint16() {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let target = match @domain.decode_domain_labels(reader) {
    Ok(t) => t
    Err(e) => return Err(e)
  }
  Ok(@types.RData::SRV(priority, weight, port, target))
}

///| Encode a CAA record RDATA (flags, tag, value, RFC 6844)
pub fn encode_rdata_caa(
  writer : @bytes_io.ByteWriter,
  flags : Byte,
  tag : String,
  value : String
) -> Result[Unit, @types.DnsError] {
  let tag_len = tag.length()
  if tag_len > 255 {
    return Err(@types.InvalidLength("CAA tag length exceeds 255: " + tag_len.to_string()))
  }
  writer.write_byte(flags)
  writer.write_byte(tag_len.to_byte())
  for i = 0; i < tag_len; i = i + 1 {
    writer.write_byte(tag[i].to_int().to_byte())
  }
  for j = 0; j < value.length(); j = j + 1 {
    writer.write_byte(value[j].to_int().to_byte())
  }
  Ok(())
}

///| Decode a CAA record RDATA from wire format
pub fn decode_rdata_caa(
  reader : @bytes_io.ByteReader,
  rdlength : UInt16
) -> Result[@types.RData, @types.DnsError] {
  if rdlength < 2 {
    return Err(@types.BufferUnderflow("CAA record requires at least 2 bytes"))
  }
  let flags = match reader.read_byte() {
    Ok(f) => f
    Err(e) => return Err(e)
  }
  let tag_len_byte = match reader.read_byte() {
    Ok(tl) => tl
    Err(e) => return Err(e)
  }
  let tag_len = tag_len_byte.to_int()
  let value_len = rdlength.to_int() - 2 - tag_len
  if value_len < 0 {
    return Err(@types.BufferUnderflow("CAA tag length exceeds RDLENGTH"))
  }
  let tag_bytes = match reader.read_bytes(tag_len) {
    Ok(tb) => tb
    Err(e) => return Err(e)
  }
  let tag_buf = StringBuilder()
  for i = 0; i < tag_len; i = i + 1 {
    tag_buf.write_char(Int::unsafe_to_char(tag_bytes[i].to_int()))
  }
  let val_bytes = match reader.read_bytes(value_len) {
    Ok(vb) => vb
    Err(e) => return Err(e)
  }
  let val_buf = StringBuilder()
  for j = 0; j < value_len; j = j + 1 {
    val_buf.write_char(Int::unsafe_to_char(val_bytes[j].to_int()))
  }
  Ok(@types.RData::CAA(flags, tag_buf.to_string(), val_buf.to_string()))
}
