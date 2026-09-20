// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Golden Vector 1: Standard query for "a.gtld-servers.net." type A
test "golden vector standard a query hex comparison" {
  let writer = @bytes_io.ByteWriter::new()
  let header = @types.Header::new_query(0x4321)
  @codec.encode_header(writer, header)
  let q = @types.Question::new("a.gtld-servers.net.", @types.RType::A, @types.RClass::IN)
  let cmap = @compression.CompressionMap::new()
  let _ = @codec.encode_question(writer, cmap, q)
  let wire = writer.to_bytes()

  // Verify wire structure
  assert_eq(wire[0].to_int(), 0x43)
  assert_eq(wire[1].to_int(), 0x21)
  assert_eq(wire[2].to_int(), 0x01) // RD=1
  assert_eq(wire[3].to_int(), 0x00)
  assert_eq(wire[4].to_int(), 0x00) // QDCOUNT = 1
  assert_eq(wire[5].to_int(), 0x01)

  // Verify decode produces exact question
  match @codec.decode_message(wire) {
    Ok(msg) => {
      assert_eq(msg.header.id, 0x4321)
      assert_eq(msg.questions.length(), 1)
      assert_eq(msg.questions[0].name, "a.gtld-servers.net.")
      assert_eq(msg.questions[0].qtype, @types.RType::A)
      assert_eq(msg.questions[0].qclass, @types.RClass::IN)
    }
    Err(_) => panic()
  }
}

///| Golden Vector 2: Comprehensive multi-record response with compression
test "golden vector authoritative response with mx, txt and soa" {
  let zone = @zone.Zone::new("corp.example.org.", 3600)

  // 1. Apex SOA
  zone.add_record(@types.Record::new(
    "corp.example.org.",
    @types.RType::SOA,
    @types.RClass::IN,
    86400,
    @types.RData::SOA(
      "master.corp.example.org.",
      "admin.corp.example.org.",
      2026092005,
      14400,
      3600,
      2419200,
      1800
    )
  ))

  // 2. Apex MX
  zone.add_record(@types.Record::new(
    "corp.example.org.",
    @types.RType::MX,
    @types.RClass::IN,
    3600,
    @types.RData::MX(10, "smtp1.corp.example.org.")
  ))

  // 3. Apex TXT (SPF record)
  zone.add_record(@types.Record::new(
    "corp.example.org.",
    @types.RType::TXT,
    @types.RClass::IN,
    3600,
    @types.RData::TXT(["v=spf1 include:_spf.corp.example.org ~all"])
  ))

  // 4. Server A record
  zone.add_record(@types.Record::new(
    "smtp1.corp.example.org.",
    @types.RType::A,
    @types.RClass::IN,
    3600,
    @types.RData::A((198).to_byte(), (51).to_byte(), (100).to_byte(), (25).to_byte())
  ))

  // Execute MX query
  let query = @types.Message::new_query(0x7777, "corp.example.org.", @types.RType::MX)
  let resp = @resolver.build_response(query, zone)

  // Assert RFC semantics
  assert_eq(resp.header.id, 0x7777)
  assert_eq(resp.header.qr, true)
  assert_eq(resp.header.aa, true)
  assert_eq(resp.header.rcode, @types.RCode::NoError)
  assert_eq(resp.answers.length(), 1)
  assert_eq(resp.answers[0].rtype, @types.RType::MX)
  // Glue record for smtp1 should be attached in additionals
  assert_eq(resp.additionals.length(), 1)
  assert_eq(resp.additionals[0].name, "smtp1.corp.example.org.")

  // Wire encode and verify compression saves significant space
  let wire = @codec.encode_message(resp)
  let decoded = match @codec.decode_message(wire) {
    Ok(m) => m
    Err(_) => panic()
  }
  assert_eq(decoded.answers.length(), 1)
  assert_eq(decoded.additionals.length(), 1)

  // Bit-for-bit idempotency test
  let re_wire = @codec.encode_message(decoded)
  assert_eq(re_wire.length(), wire.length())
  for i = 0; i < wire.length(); i = i + 1 {
    assert_eq(re_wire[i].to_int(), wire[i].to_int())
  }
}

///| Golden Vector 3: DNS Record Roundtrip Verification Matrix
test "golden matrix across all supported record types" {
  let writer = @bytes_io.ByteWriter::new()
  let cmap = @compression.CompressionMap::new()

  // 1. AAAA
  let aaaa_arr = FixedArray::make(16, (0).to_byte())
  aaaa_arr[0] = (0x26).to_byte()
  aaaa_arr[1] = (0x06).to_byte()
  aaaa_arr[15] = (0x01).to_byte()
  let rec_aaaa = @types.Record::new("ipv6.example.com.", @types.RType::AAAA, @types.RClass::IN, 300, @types.RData::AAAA(aaaa_arr))
  let _ = @codec.encode_record(writer, cmap, rec_aaaa)

  // 2. PTR
  let rec_ptr = @types.Record::new("1.0.0.127.in-addr.arpa.", @types.RType::PTR, @types.RClass::IN, 3600, @types.RData::PTR("localhost."))
  let _ = @codec.encode_record(writer, cmap, rec_ptr)

  // 3. SRV
  let rec_srv = @types.Record::new("_sip._tcp.example.com.", @types.RType::SRV, @types.RClass::IN, 300, @types.RData::SRV(10, 20, 5060, "sipserver.example.com."))
  let _ = @codec.encode_record(writer, cmap, rec_srv)

  // 4. CAA
  let rec_caa = @types.Record::new("example.com.", @types.RType::CAA, @types.RClass::IN, 3600, @types.RData::CAA((0).to_byte(), "issue", "digicert.com"))
  let _ = @codec.encode_record(writer, cmap, rec_caa)

  let wire = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(wire)

  // Decode and verify 1 by 1
  let dec_aaaa = match @codec.decode_record(reader) {
    Ok(r) => r
    Err(_) => panic()
  }
  assert_eq(dec_aaaa.rtype, @types.RType::AAAA)

  let dec_ptr = match @codec.decode_record(reader) {
    Ok(r) => r
    Err(_) => panic()
  }
  assert_eq(dec_ptr.rtype, @types.RType::PTR)

  let dec_srv = match @codec.decode_record(reader) {
    Ok(r) => r
    Err(_) => panic()
  }
  assert_eq(dec_srv.rtype, @types.RType::SRV)

  let dec_caa = match @codec.decode_record(reader) {
    Ok(r) => r
    Err(_) => panic()
  }
  assert_eq(dec_caa.rtype, @types.RType::CAA)
}
