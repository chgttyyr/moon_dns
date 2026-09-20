// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "mock memory pipeline end-to-end query" {
  let zone = @zone.Zone::new("example.com.", 300)
  let rec_a = @types.Record::new(
    "api.example.com.",
    @types.RType::A,
    @types.RClass::IN,
    60,
    @types.RData::A((10).to_byte(), (20).to_byte(), (30).to_byte(), (40).to_byte())
  )
  zone.add_record(rec_a)

  // Construct binary query request
  let query = @types.Message::new_query(0xcafe, "api.example.com.", @types.RType::A)
  let query_bytes = @codec.encode_message(query)

  // Feed into zero-I/O pipeline
  let server = DnsServer::new(zone)
  match server.process_udp(query_bytes) {
    Ok(resp_bytes) => {
      let resp_msg = match @codec.decode_message(resp_bytes) {
        Ok(m) => m
        Err(_) => panic()
      }
      assert_eq(resp_msg.header.id, 0xcafe)
      assert_eq(resp_msg.header.qr, true)
      assert_eq(resp_msg.header.aa, true)
      assert_eq(resp_msg.header.rcode, @types.RCode::NoError)
      assert_eq(resp_msg.answers.length(), 1)
      assert_eq(resp_msg.answers[0].name, "api.example.com.")
      match resp_msg.answers[0].rdata {
        @types.RData::A(b0, b1, b2, b3) => {
          assert_eq(b0.to_int(), 10)
          assert_eq(b1.to_int(), 20)
          assert_eq(b2.to_int(), 30)
          assert_eq(b3.to_int(), 40)
        }
        _ => panic()
      }
      assert_eq(server.query_count, 1)
      assert_eq(server.error_count, 0)
    }
    Err(_) => panic()
  }
}

test "tcp framing encode and decode" {
  let payload = Bytes::from_array([(1).to_byte(), (2).to_byte(), (3).to_byte(), (4).to_byte()])
  let frame = encode_tcp_frame(payload)
  // 2 bytes length prefix (0x0004) + 4 bytes = 6 bytes
  assert_eq(frame.length(), 6)
  assert_eq(frame[0].to_int(), 0)
  assert_eq(frame[1].to_int(), 4)

  let reader = @bytes_io.ByteReader::new(frame)
  match decode_tcp_frame(reader) {
    Ok(decoded_payload) => {
      assert_eq(decoded_payload.length(), 4)
      assert_eq(decoded_payload[0].to_int(), 1)
      assert_eq(decoded_payload[3].to_int(), 4)
    }
    Err(_) => panic()
  }
}

test "mock pipeline malformed input error recording" {
  let zone = @zone.Zone::new("example.com.", 300)
  let server = DnsServer::new(zone)
  let invalid_bytes = Bytes::from_array([(0xff).to_byte(), (0xff).to_byte()])

  let res = server.process_udp(invalid_bytes)
  assert_true(res is Err(_))
  assert_eq(server.query_count, 1)
  assert_eq(server.error_count, 1)
}
