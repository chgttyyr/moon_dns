// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "domain normalize and case insensitive equality" {
  assert_eq(normalize_fqdn("example.com"), "example.com.")
  assert_eq(normalize_fqdn("example.com."), "example.com.")
  assert_eq(normalize_fqdn("."), ".")

  assert_true(domain_equal("WWW.Example.COM", "www.example.com."))
  assert_true(domain_equal("ns1.google.com.", "NS1.GOOGLE.COM"))
  assert_false(domain_equal("example.com.", "example.org."))
}

test "split labels and subdomain hierarchy" {
  let labels = split_labels("mail.server.example.com.")
  assert_eq(labels.length(), 4)
  assert_eq(labels[0], "mail")
  assert_eq(labels[1], "server")
  assert_eq(labels[2], "example")
  assert_eq(labels[3], "com")

  assert_true(is_subdomain_of("mail.server.example.com.", "example.com."))
  assert_true(is_subdomain_of("example.com.", "example.com."))
  assert_false(is_subdomain_of("example.org.", "example.com."))
  assert_false(is_subdomain_of("com.", "example.com."))
}

test "domain label wire encoding and decoding" {
  let writer = @bytes_io.ByteWriter::new()
  match encode_domain_labels(writer, "test.local.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let bytes = writer.to_bytes()
  // "test" (4) + 't','e','s','t' + "local" (5) + 'l','o','c','a','l' + 0 = 1 + 4 + 1 + 5 + 1 = 12 bytes
  assert_eq(bytes.length(), 12)

  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_domain_labels(reader) {
    Ok(decoded) => assert_eq(decoded, "test.local.")
    Err(_) => panic()
  }
}

test "root domain wire encoding" {
  let writer = @bytes_io.ByteWriter::new()
  match encode_domain_labels(writer, ".") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let bytes = writer.to_bytes()
  assert_eq(bytes.length(), 1)
  assert_eq(bytes[0].to_int(), 0)

  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_domain_labels(reader) {
    Ok(decoded) => assert_eq(decoded, ".")
    Err(_) => panic()
  }
}

test "reject oversized label" {
  let writer = @bytes_io.ByteWriter::new()
  // Create a 64-character label (exceeding 63)
  let long_label = "a0123456789012345678901234567890123456789012345678901234567890123.com."
  match encode_domain_labels(writer, long_label) {
    Ok(_) => panic()
    Err(e) => match e {
      @types.MalformedLabel(_) => ()
      _ => panic()
    }
  }
}
