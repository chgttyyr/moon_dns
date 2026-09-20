// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Encode a 12-byte fixed DNS header into wire format
pub fn encode_header(
  writer : @bytes_io.ByteWriter,
  header : @types.Header
) -> Unit {
  writer.write_uint16(header.id)

  let qr_bit = if header.qr { 1 } else { 0 }
  let op_bits = header.opcode.to_wire().to_int() & 0x0f
  let aa_bit = if header.aa { 1 } else { 0 }
  let tc_bit = if header.tc { 1 } else { 0 }
  let rd_bit = if header.rd { 1 } else { 0 }
  let b2 = (qr_bit << 7) | (op_bits << 3) | (aa_bit << 2) | (tc_bit << 1) | rd_bit
  writer.write_byte(b2.to_byte())

  let ra_bit = if header.ra { 1 } else { 0 }
  let z_bits = (header.z.to_int() & 0x07) << 4
  let rc_bits = header.rcode.to_wire().to_int() & 0x0f
  let b3 = (ra_bit << 7) | z_bits | rc_bits
  writer.write_byte(b3.to_byte())

  writer.write_uint16(header.qdcount)
  writer.write_uint16(header.ancount)
  writer.write_uint16(header.nscount)
  writer.write_uint16(header.arcount)
}

///| Decode a 12-byte fixed DNS header from wire format
pub fn decode_header(
  reader : @bytes_io.ByteReader
) -> Result[@types.Header, @types.DnsError] {
  let id = match reader.read_uint16() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let b2_byte = match reader.read_byte() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let b3_byte = match reader.read_byte() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let b2 = b2_byte.to_int()
  let b3 = b3_byte.to_int()

  let qr = ((b2 >> 7) & 0x01) == 1
  let opcode = @types.OpCode::from_wire(((b2 >> 3) & 0x0f).to_byte())
  let aa = ((b2 >> 2) & 0x01) == 1
  let tc = ((b2 >> 1) & 0x01) == 1
  let rd = (b2 & 0x01) == 1

  let ra = ((b3 >> 7) & 0x01) == 1
  let z = ((b3 >> 4) & 0x07).to_byte()
  let rcode = @types.RCode::from_wire((b3 & 0x0f).to_uint16())

  let qdcount = match reader.read_uint16() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let ancount = match reader.read_uint16() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let nscount = match reader.read_uint16() {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let arcount = match reader.read_uint16() {
    Ok(v) => v
    Err(e) => return Err(e)
  }

  Ok({
    id,
    qr,
    opcode,
    aa,
    tc,
    rd,
    ra,
    z,
    rcode,
    qdcount,
    ancount,
    nscount,
    arcount,
  })
}

///| Encode a single Question entry into wire format
pub fn encode_question(
  writer : @bytes_io.ByteWriter,
  cmap : @compression.CompressionMap,
  q : @types.Question
) -> Result[Unit, @types.DnsError] {
  let res = @compression.encode_domain_compressed(writer, cmap, q.name)
  match res {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  writer.write_uint16(q.qtype.to_wire())
  writer.write_uint16(q.qclass.to_wire())
  Ok(())
}

///| Decode a single Question entry from wire format
pub fn decode_question(
  reader : @bytes_io.ByteReader
) -> Result[@types.Question, @types.DnsError] {
  let name = match @compression.decode_domain_compressed(reader) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let qtype_code = match reader.read_uint16() {
    Ok(t) => t
    Err(e) => return Err(e)
  }
  let qclass_code = match reader.read_uint16() {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  Ok(@types.Question::new(name, @types.RType::from_wire(qtype_code), @types.RClass::from_wire(qclass_code)))
}

///| Encode a Resource Record into wire format
pub fn encode_record(
  writer : @bytes_io.ByteWriter,
  cmap : @compression.CompressionMap,
  rec : @types.Record
) -> Result[Unit, @types.DnsError] {
  let res_name = @compression.encode_domain_compressed(writer, cmap, rec.name)
  match res_name {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  writer.write_uint16(rec.rtype.to_wire())
  writer.write_uint16(rec.rclass.to_wire())
  writer.write_uint32(rec.ttl)

  // Allocate 2 bytes placeholder for RDLENGTH
  let rdlength_pos = writer.length()
  writer.write_uint16(0)
  let rdata_start = writer.length()

  match rec.rdata {
    @types.RData::A(b0, b1, b2, b3) => @records.encode_rdata_a(writer, b0, b1, b2, b3)
    @types.RData::AAAA(arr) => {
      let r = @records.encode_rdata_aaaa(writer, arr)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::CNAME(target) => {
      let r = @records.encode_rdata_cname(writer, target)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::NS(nsdname) => {
      let r = @records.encode_rdata_ns(writer, nsdname)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::PTR(target) => {
      let r = @records.encode_rdata_ptr(writer, target)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::MX(pref, exch) => {
      let r = @records.encode_rdata_mx(writer, pref, exch)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::TXT(chunks) => {
      let r = @records.encode_rdata_txt(writer, chunks)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::SOA(mname, rname, ser, refr, ret, exp, min) => {
      let r = @records.encode_rdata_soa(writer, mname, rname, ser, refr, ret, exp, min)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::SRV(prio, weight, port, target) => {
      let r = @records.encode_rdata_srv(writer, prio, weight, port, target)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::CAA(flags, tag, val) => {
      let r = @records.encode_rdata_caa(writer, flags, tag, val)
      match r {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
    }
    @types.RData::OPT(_, _, _, _, data) => {
      writer.write_bytes(data)
    }
    @types.RData::Raw(bytes) => {
      writer.write_bytes(bytes)
    }
  }

  let actual_rdlen = writer.length() - rdata_start
  let patch_res = writer.patch_uint16(rdlength_pos, actual_rdlen.to_uint16())
  match patch_res {
    Ok(_) => ()
    Err(e) => return Err(e)
  }
  Ok(())
}

///| Decode a Resource Record from wire format
pub fn decode_record(
  reader : @bytes_io.ByteReader
) -> Result[@types.Record, @types.DnsError] {
  let name = match @compression.decode_domain_compressed(reader) {
    Ok(n) => n
    Err(e) => return Err(e)
  }
  let rtype_code = match reader.read_uint16() {
    Ok(t) => t
    Err(e) => return Err(e)
  }
  let rtype = @types.RType::from_wire(rtype_code)
  let rclass_code = match reader.read_uint16() {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  let rclass = @types.RClass::from_wire(rclass_code)
  let ttl = match reader.read_uint32() {
    Ok(t) => t
    Err(e) => return Err(e)
  }
  let rdlength = match reader.read_uint16() {
    Ok(l) => l
    Err(e) => return Err(e)
  }

  let rdata : @types.RData = match rtype {
    @types.RType::A => match @records.decode_rdata_a(reader, rdlength) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::AAAA => match @records.decode_rdata_aaaa(reader, rdlength) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::CNAME => match @records.decode_rdata_cname(reader) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::NS => match @records.decode_rdata_ns(reader) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::PTR => match @records.decode_rdata_ptr(reader) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::MX => match @records.decode_rdata_mx(reader) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::TXT => match @records.decode_rdata_txt(reader, rdlength) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::SOA => match @records.decode_rdata_soa(reader) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::SRV => match @records.decode_rdata_srv(reader) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::CAA => match @records.decode_rdata_caa(reader, rdlength) {
      Ok(rd) => rd
      Err(e) => return Err(e)
    }
    @types.RType::OPT => {
      let raw_opt = match reader.read_bytes(rdlength.to_int()) {
        Ok(bs) => bs
        Err(e) => return Err(e)
      }
      let opt_struct = @records.OptRecord::unpack(rclass_code, ttl, raw_opt)
      @types.RData::OPT(
        opt_struct.udp_payload_size,
        opt_struct.extended_rcode,
        opt_struct.version,
        opt_struct.do_flag,
        opt_struct.data,
      )
    }
    _ => {
      let raw_bytes = match reader.read_bytes(rdlength.to_int()) {
        Ok(bs) => bs
        Err(e) => return Err(e)
      }
      @types.RData::Raw(raw_bytes)
    }
  }

  Ok(@types.Record::new(name, rtype, rclass, ttl, rdata))
}

///| Encode a complete DNS Message into wire format bytes
pub fn encode_message(msg : @types.Message) -> Bytes {
  let writer = @bytes_io.ByteWriter::new()
  let cmap = @compression.CompressionMap::new()

  // Make sure header counts accurately mirror the arrays
  msg.sync_counts()
  encode_header(writer, msg.header)

  for i = 0; i < msg.questions.length(); i = i + 1 {
    let _ = encode_question(writer, cmap, msg.questions[i])
  }
  for i = 0; i < msg.answers.length(); i = i + 1 {
    let _ = encode_record(writer, cmap, msg.answers[i])
  }
  for i = 0; i < msg.authorities.length(); i = i + 1 {
    let _ = encode_record(writer, cmap, msg.authorities[i])
  }
  for i = 0; i < msg.additionals.length(); i = i + 1 {
    let _ = encode_record(writer, cmap, msg.additionals[i])
  }

  writer.to_bytes()
}

///| Decode a complete DNS Message from wire format bytes (strictly returns Err on malformed input, never panics)
pub fn decode_message(bytes : Bytes) -> Result[@types.Message, @types.DnsError] {
  if bytes.length() < 12 {
    return Err(@types.BufferUnderflow("DNS packet shorter than 12-byte header: " + bytes.length().to_string()))
  }
  let reader = @bytes_io.ByteReader::new(bytes)
  let header = match decode_header(reader) {
    Ok(h) => h
    Err(e) => return Err(e)
  }

  let questions : Array[@types.Question] = []
  for i = 0; i < header.qdcount.to_int(); i = i + 1 {
    let q = match decode_question(reader) {
      Ok(val) => val
      Err(e) => return Err(e)
    }
    questions.push(q)
  }

  let answers : Array[@types.Record] = []
  for i = 0; i < header.ancount.to_int(); i = i + 1 {
    let rec = match decode_record(reader) {
      Ok(val) => val
      Err(e) => return Err(e)
    }
    answers.push(rec)
  }

  let authorities : Array[@types.Record] = []
  for i = 0; i < header.nscount.to_int(); i = i + 1 {
    let rec = match decode_record(reader) {
      Ok(val) => val
      Err(e) => return Err(e)
    }
    authorities.push(rec)
  }

  let additionals : Array[@types.Record] = []
  for i = 0; i < header.arcount.to_int(); i = i + 1 {
    let rec = match decode_record(reader) {
      Ok(val) => val
      Err(e) => return Err(e)
    }
    additionals.push(rec)
  }

  Ok({
    header,
    questions,
    answers,
    authorities,
    additionals,
  })
}
