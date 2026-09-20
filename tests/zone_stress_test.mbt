// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "zone stress: load 100 domain records and execute rapid batch queries" {
  let zone = @zone.Zone::new("cloud.internal.", 300)
  let server = @transport.DnsServer::new(zone)

  // Preload 100 host records: node-00.cloud.internal through node-99.cloud.internal
  for i = 0; i < 100; i = i + 1 {
    let hostname = "node-" + i.to_string() + ".cloud.internal."
    let last_octet = (i % 250 + 1).to_byte()
    let rec = @types.Record::new(
      hostname,
      @types.RType::A,
      @types.RClass::IN,
      300,
      @types.RData::A((10).to_byte(), (244).to_byte(), (0).to_byte(), last_octet)
    )
    zone.add_record(rec)
  }

  // Add wildcard fallback: *.preview.cloud.internal.
  let wildcard_preview = @types.Record::new(
    "*.preview.cloud.internal.",
    @types.RType::A,
    @types.RClass::IN,
    60,
    @types.RData::A((10).to_byte(), (244).to_byte(), (254).to_byte(), (1).to_byte())
  )
  zone.add_record(wildcard_preview)

  // Query each of the 100 nodes and assert 100% resolution accuracy
  for i = 0; i < 100; i = i + 1 {
    let query_host = "node-" + i.to_string() + ".cloud.internal."
    let q = @types.Message::new_query((1000 + i).to_uint16(), query_host, @types.RType::A)
    let q_bytes = @codec.encode_message(q)

    match server.process_udp(q_bytes) {
      Ok(resp_bytes) => {
        let resp = match @codec.decode_message(resp_bytes) {
          Ok(m) => m
          Err(_) => panic()
        }
        assert_eq(resp.header.id, (1000 + i).to_uint16())
        assert_eq(resp.header.aa, true)
        assert_eq(resp.header.rcode, @types.RCode::NoError)
        assert_eq(resp.answers.length(), 1)
        assert_eq(resp.answers[0].name, query_host)
      }
      Err(_) => panic()
    }
  }

  // Query wildcard subdomains
  let wildcard_q = @types.Message::new_query(0x9999, "pr-1234.preview.cloud.internal.", @types.RType::A)
  match server.process_udp(@codec.encode_message(wildcard_q)) {
    Ok(raw) => {
      let resp = match @codec.decode_message(raw) {
        Ok(m) => m
        Err(_) => panic()
      }
      assert_eq(resp.answers.length(), 1)
      assert_eq(resp.answers[0].name, "pr-1234.preview.cloud.internal.")
      match resp.answers[0].rdata {
        @types.RData::A(b0, b1, b2, b3) => {
          assert_eq(b0.to_int(), 10)
          assert_eq(b1.to_int(), 244)
          assert_eq(b2.to_int(), 254)
          assert_eq(b3.to_int(), 1)
        }
        _ => panic()
      }
    }
    Err(_) => panic()
  }

  assert_eq(server.query_count, 101)
  assert_eq(server.error_count, 0)
}
