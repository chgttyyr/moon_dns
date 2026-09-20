// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "security fuzz: all malformed packet shapes must return Err safely" {
  let zone = @zone.Zone::new("test.net.", 300)
  let server = @transport.DnsServer::new(zone)

  // 1. Truncated header (1..11 bytes)
  for len = 0; len < 12; len = len + 1 {
    let arr : Array[Byte] = []
    for i = 0; i < len; i = i + 1 {
      arr.push((0xaa).to_byte())
    }
    let res = server.process_udp(Bytes::from_array(arr))
    assert_true(res is Err(_))
  }

  // 2. Claims 5 questions in QDCOUNT but payload has zero questions
  let h_writer = @bytes_io.ByteWriter::new()
  let h_fake = @types.Header::new_query(0x1234)
  h_fake.qdcount = 5
  @codec.encode_header(h_writer, h_fake)
  let res_fake_qd = server.process_udp(h_writer.to_bytes())
  assert_true(res_fake_qd is Err(_))

  // 3. Claims 1 question but domain label length exceeds remaining packet
  let l_writer = @bytes_io.ByteWriter::new()
  let h_q = @types.Header::new_query(0x2345)
  @codec.encode_header(l_writer, h_q)
  l_writer.write_byte((60).to_byte()) // claims 60 bytes label
  l_writer.write_byte(('a').to_int().to_byte()) // only provides 1 byte
  let res_overflow_label = server.process_udp(l_writer.to_bytes())
  assert_true(res_overflow_label is Err(_))

  // 4. Pointer target loop targeting offset 0 (0xc000)
  let loop_writer = @bytes_io.ByteWriter::new()
  let h_loop = @types.Header::new_query(0x3456)
  @codec.encode_header(loop_writer, h_loop)
  loop_writer.write_byte((0xc0).to_byte())
  loop_writer.write_byte((0x00).to_byte())
  let res_loop = server.process_udp(loop_writer.to_bytes())
  assert_true(res_loop is Err(_))

  // 5. Huge out-of-bounds pointer (0xcfff)
  let oob_writer = @bytes_io.ByteWriter::new()
  let h_oob = @types.Header::new_query(0x4567)
  @codec.encode_header(oob_writer, h_oob)
  oob_writer.write_byte((0xcf).to_byte())
  oob_writer.write_byte((0xff).to_byte())
  let res_oob = server.process_udp(oob_writer.to_bytes())
  assert_true(res_oob is Err(_))
}

test "security fuzz: unsupported opcode and class behavior" {
  let zone = @zone.Zone::new("test.net.", 300)

  // OpCode Update (5) sent to authoritative read server -> NotImp
  let query = @types.Message::new_query(0x7890, "test.net.", @types.RType::A)
  query.header.opcode = @types.OpCode::Update
  let resp = @resolver.build_response(query, zone)
  assert_eq(resp.header.rcode, @types.RCode::NotImp)

  // Querying with empty questions -> FormErr
  let empty_query = @types.Message::new()
  empty_query.header.id = 0x8901
  empty_query.header.opcode = @types.OpCode::Query
  let resp_empty = @resolver.build_response(empty_query, zone)
  assert_eq(resp_empty.header.rcode, @types.RCode::FormErr)
}
