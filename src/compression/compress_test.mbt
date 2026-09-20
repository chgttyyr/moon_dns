// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "compression dictionary deduplication and roundtrip" {
  let writer = @bytes_io.ByteWriter::new()
  let cmap = CompressionMap::new()

  // 1. Encode "mail.example.com."
  match encode_domain_compressed(writer, cmap, "mail.example.com.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let first_len = writer.length()
  // "mail"(5) + "example"(8) + "com"(4) + 1 = 18 bytes
  assert_eq(first_len, 18)

  // 2. Encode exact duplicate "mail.example.com."
  match encode_domain_compressed(writer, cmap, "mail.example.com.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let second_len = writer.length()
  // Second domain should be compressed to exactly 2 bytes (0xc000)
  assert_eq(second_len - first_len, 2)

  // 3. Encode suffix sharing "ftp.example.com."
  match encode_domain_compressed(writer, cmap, "ftp.example.com.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let third_len = writer.length()
  // "ftp"(4 bytes) + 2-byte pointer to "example.com." at offset 5 = 6 bytes
  assert_eq(third_len - second_len, 6)

  // 4. Verify all 3 domains can be accurately decompressed
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)

  // Read first domain
  match decode_domain_compressed(reader) {
    Ok(d1) => assert_eq(d1, "mail.example.com.")
    Err(_) => panic()
  }
  assert_eq(reader.position(), first_len)

  // Read second domain
  match decode_domain_compressed(reader) {
    Ok(d2) => assert_eq(d2, "mail.example.com.")
    Err(_) => panic()
  }
  assert_eq(reader.position(), second_len)

  // Read third domain
  match decode_domain_compressed(reader) {
    Ok(d3) => assert_eq(d3, "ftp.example.com.")
    Err(_) => panic()
  }
  assert_eq(reader.position(), third_len)
}
