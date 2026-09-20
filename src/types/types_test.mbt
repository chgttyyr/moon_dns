// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "rcode wire conversion" {
  assert_eq(RCode::NoError.to_wire(), 0)
  assert_eq(RCode::NXDomain.to_wire(), 3)
  assert_eq(RCode::from_wire(0), RCode::NoError)
  assert_eq(RCode::from_wire(3), RCode::NXDomain)
  assert_eq(RCode::from_wire(99), RCode::Unknown(99))
}

test "opcode wire conversion" {
  assert_eq(OpCode::Query.to_wire(), (0).to_byte())
  assert_eq(OpCode::from_wire((0).to_byte()), OpCode::Query)
  assert_eq(OpCode::from_wire((4).to_byte()), OpCode::Notify)
}

test "rtype wire and string conversion" {
  assert_eq(RType::A.to_wire(), 1)
  assert_eq(RType::AAAA.to_wire(), 28)
  assert_eq(RType::OPT.to_wire(), 41)
  assert_eq(RType::from_wire(1), RType::A)
  assert_eq(RType::from_wire(28), RType::AAAA)
  assert_eq(RType::A.to_string(), "A")
  assert_eq(RType::from_string("AAAA"), Some(RType::AAAA))
  assert_eq(RType::from_string("NONEXISTENT"), None)
}

test "rclass wire conversion" {
  assert_eq(RClass::IN.to_wire(), 1)
  assert_eq(RClass::from_wire(1), RClass::IN)
  assert_eq(RClass::IN.to_string(), "IN")
}

test "header constructors" {
  let qh = Header::new_query(0x1234)
  assert_eq(qh.id, 0x1234)
  assert_eq(qh.qr, false)
  assert_eq(qh.qdcount, 1)
  assert_eq(qh.ancount, 0)

  let rh = Header::new_response(0x1234, true, RCode::NoError, 1, 2, 0, 0)
  assert_eq(rh.id, 0x1234)
  assert_eq(rh.qr, true)
  assert_eq(rh.aa, true)
  assert_eq(rh.ancount, 2)
}

test "message creation and record appending" {
  let msg = Message::new_query(0xabcd, "example.com.", RType::A)
  assert_eq(msg.header.id, 0xabcd)
  assert_eq(msg.questions.length(), 1)
  assert_eq(msg.questions[0].name, "example.com.")

  let resp = Message::new_response(msg, true, RCode::NoError)
  let rec = Record::new(
    "example.com.",
    RType::A,
    RClass::IN,
    300,
    RData::A((93).to_byte(), (184).to_byte(), (216).to_byte(), (34).to_byte())
  )
  resp.add_answer(rec)
  assert_eq(resp.header.ancount, 1)
  assert_eq(resp.answers.length(), 1)
}
