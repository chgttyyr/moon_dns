// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "golden header wire codec roundtrip" {
  let header : @types.Header = {
    id: 0x1234,
    qr: true,
    opcode: @types.OpCode::Query,
    aa: true,
    tc: false,
    rd: true,
    ra: false,
    z: (0).to_byte(),
    rcode: @types.RCode::NoError,
    qdcount: 1,
    ancount: 2,
    nscount: 1,
    arcount: 0,
  }
  let writer = @bytes_io.ByteWriter::new()
  encode_header(writer, header)
  let bytes = writer.to_bytes()
  assert_eq(bytes.length(), 12)

  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_header(reader) {
    Ok(decoded) => {
      assert_eq(decoded.id, 0x1234)
      assert_eq(decoded.qr, true)
      assert_eq(decoded.aa, true)
      assert_eq(decoded.qdcount, 1)
      assert_eq(decoded.ancount, 2)
      assert_eq(decoded.nscount, 1)
      assert_eq(decoded.arcount, 0)
    }
    Err(_) => panic()
  }
}

test "golden message full roundtrip with compression" {
  let msg = @types.Message::new_query(0xbeef, "example.com.", @types.RType::A)
  let resp = @types.Message::new_response(msg, true, @types.RCode::NoError)

  // Add Answer 1: A record for example.com
  let rec_a = @types.Record::new(
    "example.com.",
    @types.RType::A,
    @types.RClass::IN,
    300,
    @types.RData::A((93).to_byte(), (184).to_byte(), (216).to_byte(), (34).to_byte())
  )
  resp.add_answer(rec_a)

  // Add Answer 2: TXT record
  let rec_txt = @types.Record::new(
    "example.com.",
    @types.RType::TXT,
    @types.RClass::IN,
    600,
    @types.RData::TXT(["v=spf1 -all"])
  )
  resp.add_answer(rec_txt)

  // Add Authority: NS record
  let rec_ns = @types.Record::new(
    "example.com.",
    @types.RType::NS,
    @types.RClass::IN,
    86400,
    @types.RData::NS("ns1.example.com.")
  )
  resp.add_authority(rec_ns)

  // Add Additional: Glue A record for ns1.example.com
  let rec_glue = @types.Record::new(
    "ns1.example.com.",
    @types.RType::A,
    @types.RClass::IN,
    86400,
    @types.RData::A((192).to_byte(), (0).to_byte(), (2).to_byte(), (53).to_byte())
  )
  resp.add_additional(rec_glue)

  // Encode to wire format
  let wire_bytes = encode_message(resp)

  // Decode back and assert equality
  match decode_message(wire_bytes) {
    Ok(decoded_msg) => {
      assert_eq(decoded_msg.header.id, 0xbeef)
      assert_eq(decoded_msg.header.qr, true)
      assert_eq(decoded_msg.header.aa, true)
      assert_eq(decoded_msg.questions.length(), 1)
      assert_eq(decoded_msg.questions[0].name, "example.com.")
      assert_eq(decoded_msg.answers.length(), 2)
      assert_eq(decoded_msg.authorities.length(), 1)
      assert_eq(decoded_msg.additionals.length(), 1)

      // Verify that re-encoding decoded_msg produces bit-for-bit identical bytes
      let re_encoded = encode_message(decoded_msg)
      assert_eq(re_encoded.length(), wire_bytes.length())
      for i = 0; i < wire_bytes.length(); i = i + 1 {
        assert_eq(re_encoded[i].to_int(), wire_bytes[i].to_int())
      }
    }
    Err(_) => panic()
  }
}

test "security: decode malformed truncated bytes safely" {
  // 0 bytes
  assert_true(decode_message(Bytes::from_array([])) is Err(_))
  // 5 bytes (incomplete header)
  assert_true(decode_message(Bytes::from_array([(1).to_byte(), (2).to_byte(), (3).to_byte(), (4).to_byte(), (5).to_byte()])) is Err(_))
}
