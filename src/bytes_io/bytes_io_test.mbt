// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "reader and writer uint16 roundtrip" {
  let writer = ByteWriter::new()
  writer.write_uint16(0x1234)
  writer.write_uint16(0xabcd)
  let bytes = writer.to_bytes()
  assert_eq(bytes.length(), 4)

  let reader = ByteReader::new(bytes)
  match reader.read_uint16() {
    Ok(v) => assert_eq(v, 0x1234)
    Err(_) => panic()
  }
  match reader.read_uint16() {
    Ok(v) => assert_eq(v, 0xabcd)
    Err(_) => panic()
  }
  // Reading beyond buffer must return Err
  match reader.read_uint16() {
    Ok(_) => panic()
    Err(e) => match e {
      @types.BufferUnderflow(_) => ()
      _ => panic()
    }
  }
}

test "reader and writer uint32 roundtrip" {
  let writer = ByteWriter::new()
  writer.write_uint32(0xdeadbeef)
  writer.write_uint32(86400) // standard 1-day DNS TTL
  let bytes = writer.to_bytes()
  assert_eq(bytes.length(), 8)

  let reader = ByteReader::new(bytes)
  match reader.read_uint32() {
    Ok(v) => assert_eq(v, 0xdeadbeef)
    Err(_) => panic()
  }
  match reader.read_uint32() {
    Ok(v) => assert_eq(v, 86400)
    Err(_) => panic()
  }
}

test "writer patch uint16" {
  let writer = ByteWriter::new()
  writer.write_uint16(0x0000) // placeholder for count
  writer.write_byte((42).to_byte())
  match writer.patch_uint16(0, 0x05) {
    Ok(_) => ()
    Err(_) => panic()
  }
  let bytes = writer.to_bytes()
  let reader = ByteReader::new(bytes)
  match reader.read_uint16() {
    Ok(v) => assert_eq(v, 0x05)
    Err(_) => panic()
  }
  match reader.read_byte() {
    Ok(b) => assert_eq(b.to_int(), 42)
    Err(_) => panic()
  }
}

test "subslice and bounds safety" {
  let writer = ByteWriter::new()
  for i = 0; i < 10; i = i + 1 {
    writer.write_byte(i.to_byte())
  }
  let bytes = writer.to_bytes()
  let reader = ByteReader::new(bytes)
  match reader.sub_slice(2, 4) {
    Ok(sub) => {
      assert_eq(sub.length(), 4)
      assert_eq(sub[0].to_int(), 2)
      assert_eq(sub[3].to_int(), 5)
    }
    Err(_) => panic()
  }
  match reader.sub_slice(8, 5) {
    Ok(_) => panic()
    Err(_) => ()
  }
}
