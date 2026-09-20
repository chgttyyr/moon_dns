// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "valid compression pointer resolution" {
  let writer = @bytes_io.ByteWriter::new()
  // At offset 0: "example.com."
  match @domain.encode_domain_labels(writer, "example.com.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let base_len = writer.length()
  // At offset base_len: "www" followed by pointer to offset 0 (0xc000)
  writer.write_byte((3).to_byte())
  writer.write_byte(('w').to_int().to_byte())
  writer.write_byte(('w').to_int().to_byte())
  writer.write_byte(('w').to_int().to_byte())
  writer.write_byte((0xc0).to_byte())
  writer.write_byte((0x00).to_byte())
  // Trailing marker byte to verify resume cursor position
  writer.write_byte((0x42).to_byte())

  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)
  // Skip over the base domain
  match reader.set_position(base_len) {
    Ok(_) => ()
    Err(_) => panic()
  }

  match decode_domain_compressed(reader) {
    Ok(name) => assert_eq(name, "www.example.com.")
    Err(_) => panic()
  }

  // Verify reader resumed right after the pointer (at trailing marker)
  match reader.read_byte() {
    Ok(b) => assert_eq(b.to_int(), 0x42)
    Err(_) => panic()
  }
}

test "security: reject self-referencing loop pointer" {
  let writer = @bytes_io.ByteWriter::new()
  // Self-pointing pointer at offset 0: 0xc000 points to 0
  writer.write_byte((0xc0).to_byte())
  writer.write_byte((0x00).to_byte())
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)

  let res = decode_domain_compressed(reader)
  assert_true(res is Err(_))
}

test "security: reject forward-pointing pointer" {
  let writer = @bytes_io.ByteWriter::new()
  // At offset 0: pointer to offset 10 (forward jump)
  writer.write_byte((0xc0).to_byte())
  writer.write_byte((0x0a).to_byte())
  // Pad with 20 zeroes
  for i = 0; i < 20; i = i + 1 {
    writer.write_byte((0).to_byte())
  }
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)

  let res = decode_domain_compressed(reader)
  assert_true(res is Err(_))
}

test "security: reject out-of-bounds pointer" {
  let writer = @bytes_io.ByteWriter::new()
  // At offset 0: pointer to offset 9999
  writer.write_byte((0xcf).to_byte())
  writer.write_byte((0xff).to_byte())
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)

  let res = decode_domain_compressed(reader)
  assert_true(res is Err(_))
}

test "security: reject circular loop pointer A -> B -> A" {
  let writer = @bytes_io.ByteWriter::new()
  // Offset 0: label "a" followed by pointer to offset 5
  writer.write_byte((1).to_byte())
  writer.write_byte(('a').to_int().to_byte())
  writer.write_byte((0xc0).to_byte())
  writer.write_byte((0x05).to_byte())
  writer.write_byte((0).to_byte()) // offset 4
  // Offset 5: label "b" followed by pointer back to offset 0 (0xc000)
  writer.write_byte((1).to_byte())
  writer.write_byte(('b').to_int().to_byte())
  writer.write_byte((0xc0).to_byte())
  writer.write_byte((0x00).to_byte())

  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)

  let res = decode_domain_compressed(reader)
  assert_true(res is Err(_))
}

test "security: reject truncated pointer" {
  let writer = @bytes_io.ByteWriter::new()
  // Only high byte of pointer without low byte
  writer.write_byte((0xc0).to_byte())
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)

  let res = decode_domain_compressed(reader)
  assert_true(res is Err(_))
}
