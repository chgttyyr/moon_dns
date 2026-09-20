// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "response truncation at 512 bytes limit" {
  let query = @types.Message::new_query(0x9999, "large.example.com.", @types.RType::TXT)
  let resp = @types.Message::new_response(query, true, @types.RCode::NoError)

  // Add 10 large TXT records, each ~100 bytes, causing the response to exceed 1000 bytes
  for i = 0; i < 10; i = i + 1 {
    let rec = @types.Record::new(
      "large.example.com.",
      @types.RType::TXT,
      @types.RClass::IN,
      300,
      @types.RData::TXT([
        "This is an intentionally oversized DNS TXT payload designed to exceed 512 bytes threshold #" + i.to_string()
      ])
    )
    resp.add_answer(rec)
  }

  // 1. Truncate with standard UDP 512 limit
  let truncated_bytes = truncate_response(resp, 512)
  assert_true(truncated_bytes.length() <= 512)

  // 2. Decode the truncated message and verify TC=1 and structural integrity
  match @codec.decode_message(truncated_bytes) {
    Ok(decoded) => {
      assert_eq(decoded.header.id, 0x9999)
      assert_eq(decoded.header.tc, true)
      assert_eq(decoded.header.aa, true)
      assert_eq(decoded.questions.length(), 1)
      assert_eq(decoded.questions[0].name, "large.example.com.")
    }
    Err(_) => panic()
  }
}

test "no truncation when buffer limit is large (e.g. EDNS0 4096)" {
  let query = @types.Message::new_query(0x8888, "bulk.example.com.", @types.RType::A)
  let resp = @types.Message::new_response(query, true, @types.RCode::NoError)

  for i = 0; i < 20; i = i + 1 {
    let rec = @types.Record::new(
      "bulk.example.com.",
      @types.RType::A,
      @types.RClass::IN,
      300,
      @types.RData::A((10).to_byte(), (0).to_byte(), (0).to_byte(), i.to_byte())
    )
    resp.add_answer(rec)
  }

  let wire_bytes = truncate_response(resp, 4096)
  match @codec.decode_message(wire_bytes) {
    Ok(decoded) => {
      assert_eq(decoded.header.tc, false)
      assert_eq(decoded.answers.length(), 20)
    }
    Err(_) => panic()
  }
}
