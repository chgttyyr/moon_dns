// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
test "parse compressed and expanded IPv6 presentation forms" {
  match parse_ipv6("2001:db8::1") {
    Ok(@types.RData::AAAA(bytes)) => {
      assert_eq(bytes[0].to_int(), 0x20)
      assert_eq(bytes[1].to_int(), 0x01)
      assert_eq(bytes[2].to_int(), 0x0d)
      assert_eq(bytes[3].to_int(), 0xb8)
      assert_eq(bytes[15].to_int(), 1)
    }
    _ => fail("compressed IPv6 address did not produce AAAA data")
  }
  match parse_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001") {
    Ok(@types.RData::AAAA(bytes)) => assert_eq(bytes[15].to_int(), 1)
    _ => fail("expanded IPv6 address did not produce AAAA data")
  }
}

///|
test "parse IPv6 zero and loopback addresses" {
  match parse_ipv6("::") {
    Ok(@types.RData::AAAA(bytes)) =>
      for i = 0; i < bytes.length(); i = i + 1 {
        assert_eq(bytes[i].to_int(), 0)
      }
    _ => fail("IPv6 unspecified address did not parse")
  }
  match parse_ipv6("::1") {
    Ok(@types.RData::AAAA(bytes)) => assert_eq(bytes[15].to_int(), 1)
    _ => fail("IPv6 loopback address did not parse")
  }
}

///|
test "reject malformed IPv6 presentation forms" {
  assert_true(parse_ipv6("") is Err(_))
  assert_true(parse_ipv6("1:2:3:4:5:6:7") is Err(_))
  assert_true(parse_ipv6("1:2:3:4:5:6:7:8:9") is Err(_))
  assert_true(parse_ipv6("1::2::3") is Err(_))
  assert_true(parse_ipv6("1:::2") is Err(_))
  assert_true(parse_ipv6("2001:db8::gg") is Err(_))
  assert_true(parse_ipv6("::ffff:192.0.2.1") is Err(_))
}
