// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
test "parse required check and serve arguments" {
  assert_eq(
    parse_cli(["moondns", "check", "-z", "zone.db", "-o", "example.com."]),
    Ok(Check("zone.db", "example.com.")),
  )
  assert_eq(
    parse_cli([
      "moondns", "serve", "-z", "zone.db", "-o", "example.com.", "-p", "5353",
    ]),
    Ok(Serve("zone.db", "example.com.", "127.0.0.1", 5353, 64)),
  )
}

///|
test "parse query arguments and defaults" {
  assert_eq(
    parse_cli(["moondns", "query", "www.example.com", "AAAA"]),
    Ok(Query("127.0.0.1", 5353, "www.example.com", @types.RType::AAAA)),
  )
  assert_eq(
    parse_cli([
      "moondns", "query", "-s", "192.0.2.10", "-p", "53", "example.com.", "A",
    ]),
    Ok(Query("192.0.2.10", 53, "example.com.", @types.RType::A)),
  )
}

///|
test "parse max connections and option aliases" {
  assert_eq(
    parse_cli([
      "moondns", "serve", "--zone", "z", "--origin", "example.com.", "--listen",
      "0.0.0.0", "--port", "5354", "--max-connections", "12",
    ]),
    Ok(Serve("z", "example.com.", "0.0.0.0", 5354, 12)),
  )
}

///|
test "help and missing command options are handled" {
  assert_eq(parse_cli([]), Ok(Help))
  assert_eq(parse_cli(["moondns", "--help"]), Ok(Help))
  assert_true(parse_cli(["moondns", "check", "-z", "zone.db"]) is Err(_))
  assert_true(parse_cli(["moondns", "serve", "-o", "example.com."]) is Err(_))
}

///|
test "invalid cli inputs are rejected" {
  assert_true(
    parse_cli([
      "moondns", "serve", "-z", "z", "-o", "example.com.", "-p", "65536",
    ])
    is Err(_),
  )
  assert_true(
    parse_cli([
      "moondns", "serve", "-z", "z", "-o", "example.com.", "-p", "18446744073709551616",
    ])
    is Err(_),
  )
  assert_true(
    parse_cli([
      "moondns", "serve", "-z", "z", "-o", "example.com.", "--max-connections", "0",
    ])
    is Err(_),
  )
  assert_true(
    parse_cli(["moondns", "query", "www.example.com", "NOTATYPE"]) is Err(_),
  )
  assert_true(
    parse_cli(["moondns", "query", "-x", "www.example.com", "A"]) is Err(_),
  )
  assert_true(parse_cli(["moondns", "unknown"]) is Err(_))
  assert_true(
    parse_cli([
      "moondns", "check", "-z", "z", "-o", "example.com.", "-p", "5353",
    ])
    is Err(_),
  )
  assert_true(
    parse_cli([
      "moondns", "query", "--listen", "127.0.0.1", "www.example.com", "A",
    ])
    is Err(_),
  )
}
