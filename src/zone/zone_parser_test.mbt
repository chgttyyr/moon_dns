// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
test "parse complete master-file zone text" {
  let zone_text =
    #|$ORIGIN example.com.
    #|$TTL 1800
    #|; SOA record
    #|@ IN SOA ns1 hostmaster 2026092001 7200 3600 1209600 1800
    #|; NS records
    #|@ IN NS ns1
    #|; A records
    #|ns1 IN A 192.0.2.1
    #|www IN A 93.184.216.34
    #|; CNAME record
    #|mail IN CNAME www
    #|; MX record
    #|@ IN MX 10 mail
    #|; TXT record
    #|@ IN TXT "v=spf1 mx ~all"
  match parse_zone_text("example.com.", zone_text) {
    Ok(zone) => {
      assert_eq(zone.origin, "example.com.")
      assert_eq(zone.default_ttl, 1800)

      // Lookup www.example.com. A
      match zone.lookup("www.example.com.", @types.RType::A) {
        ExactMatch(recs) => {
          assert_eq(recs.length(), 1)
          assert_eq(recs[0].ttl, 1800)
          match recs[0].rdata {
            @types.RData::A(b0, b1, b2, b3) => {
              assert_eq(b0.to_int(), 93)
              assert_eq(b1.to_int(), 184)
              assert_eq(b2.to_int(), 216)
              assert_eq(b3.to_int(), 34)
            }
            _ => panic()
          }
        }
        _ => panic()
      }

      // Lookup mail.example.com. -> CNAME
      match zone.lookup("mail.example.com.", @types.RType::A) {
        CNameMatch(rec, target) => {
          assert_eq(rec.name, "mail.example.com.")
          assert_eq(target, "www.example.com.")
        }
        _ => panic()
      }

      // Lookup SOA
      match zone.lookup("example.com.", @types.RType::SOA) {
        ExactMatch(recs) => {
          assert_eq(recs.length(), 1)
          match recs[0].rdata {
            @types.RData::SOA(mname, _, serial, _, _, _, _) => {
              assert_eq(mname, "ns1.example.com.")
              assert_eq(serial, 2026092001)
            }
            _ => panic()
          }
        }
        _ => panic()
      }
    }
    Err(_) => panic()
  }
}

///|
test "parse a parenthesized SOA as one multiline record" {
  let zone_text =
    #|$ORIGIN example.com.
    #|@ IN SOA ns1 hostmaster (
    #|  2026092701 ; serial
    #|  7200
    #|  3600
    #|  1209600
    #|  3600
    #|)
    #|@ IN NS ns1
  match parse_zone_text("example.com.", zone_text) {
    Ok(zone) =>
      match zone.lookup("example.com.", @types.RType::SOA) {
        ExactMatch(records) =>
          match records[0].rdata {
            @types.RData::SOA(_, _, serial, refresh, retry, expire, minimum) => {
              assert_eq(serial, 2026092701)
              assert_eq(refresh, 7200)
              assert_eq(retry, 3600)
              assert_eq(expire, 1209600)
              assert_eq(minimum, 3600)
            }
            _ => fail("apex SOA RDATA was not parsed")
          }
        _ => fail("apex SOA record was not added to the Zone")
      }
    Err(error) => fail(error.message())
  }
}

///|
test "omitted owner with an explicit TTL reuses previous owner" {
  let zone_text =
    #|$ORIGIN example.com.
    #|www IN A 192.0.2.9
    #|  300 IN TXT "hello"
  match parse_zone_text("example.com.", zone_text) {
    Ok(zone) =>
      match zone.lookup("www.example.com.", @types.RType::TXT) {
        ExactMatch(records) => {
          assert_eq(records[0].name, "www.example.com.")
          assert_eq(records[0].ttl, 300)
          match records[0].rdata {
            @types.RData::TXT(chunks) => assert_eq(chunks[0], "hello")
            _ => fail("TXT RDATA was not parsed")
          }
        }
        _ => fail("omitted owner did not reuse www.example.com.")
      }
    Err(error) => fail(error.message())
  }
}

///|
test "reject an unterminated quoted string with a source line" {
  let zone_text =
    #|$ORIGIN example.com.
    #|www IN A 192.0.2.9
    #|www IN TXT "unterminated
  match parse_zone_text("example.com.", zone_text) {
    Ok(_) => fail("unterminated quote was accepted")
    Err(error) => assert_true(error.message().contains("Line 3"))
  }
}

///|
test "relative origin changes expansion context but not zone apex" {
  let zone_text =
    #|$ORIGIN example.com.
    #|$ORIGIN sub
    #|www IN A 192.0.2.10
  match parse_zone_text("example.com.", zone_text) {
    Ok(zone) => {
      assert_eq(zone.origin, "example.com.")
      match zone.lookup("www.sub.example.com.", @types.RType::A) {
        ExactMatch(records) =>
          assert_eq(records[0].name, "www.sub.example.com.")
        _ => fail("relative $ORIGIN did not resolve under example.com.")
      }
    }
    Err(error) => fail(error.message())
  }
}

///|
test "parse the advertised IPv6 and advanced Zone record types" {
  let zone_text =
    #|$ORIGIN example.com.
    #|@ IN AAAA 2001:db8::1
    #|full IN AAAA 2001:0db8:0000:0000:0000:0000:0000:0001
    #|1.2 IN PTR host
    #|_sip._tcp IN SRV 1 2 5060 server
    #|@ IN CAA 0 issue "letsencrypt.org"
  match parse_zone_text("example.com.", zone_text) {
    Ok(zone) => {
      match zone.lookup("example.com.", @types.RType::AAAA) {
        ExactMatch(records) => {
          match records[0].rdata {
            @types.RData::AAAA(address) => {
              assert_eq(address[0].to_int(), 0x20)
              assert_eq(address[1].to_int(), 0x01)
              assert_eq(address[2].to_int(), 0x0d)
              assert_eq(address[3].to_int(), 0xb8)
              assert_eq(address[15].to_int(), 0x01)
            }
            _ => fail("AAAA RDATA was not parsed")
          }
          match zone.lookup("full.example.com.", @types.RType::AAAA) {
            ExactMatch(full_records) =>
              match full_records[0].rdata {
                @types.RData::AAAA(address) =>
                  assert_eq(address[15].to_int(), 0x01)
                _ => fail("expanded AAAA RDATA was not parsed")
              }
            _ => fail("expanded AAAA record was not added to the Zone")
          }
        }
        _ => fail("apex AAAA records were not added to the Zone")
      }
      match zone.lookup("1.2.example.com.", @types.RType::PTR) {
        ExactMatch(records) =>
          match records[0].rdata {
            @types.RData::PTR(target) => assert_eq(target, "host.example.com.")
            _ => fail("PTR RDATA was not parsed")
          }
        _ => fail("PTR record was not added to the Zone")
      }
      match zone.lookup("_sip._tcp.example.com.", @types.RType::SRV) {
        ExactMatch(records) =>
          match records[0].rdata {
            @types.RData::SRV(priority, weight, port, target) => {
              assert_eq(priority, 1)
              assert_eq(weight, 2)
              assert_eq(port, 5060)
              assert_eq(target, "server.example.com.")
            }
            _ => fail("SRV RDATA was not parsed")
          }
        _ => fail("SRV record was not added to the Zone")
      }
      match zone.lookup("example.com.", @types.RType::CAA) {
        ExactMatch(records) =>
          match records[0].rdata {
            @types.RData::CAA(flags, tag, value) => {
              assert_eq(flags.to_int(), 0)
              assert_eq(tag, "issue")
              assert_eq(value, "letsencrypt.org")
            }
            _ => fail("CAA RDATA was not parsed")
          }
        _ => fail("CAA record was not added to the Zone")
      }
    }
    Err(error) => fail(error.message())
  }
}

///|
test "parse compound TTL units and apply them to following records" {
  let zone_text =
    #|$ORIGIN example.com.
    #|$TTL 1h30m
    #|www IN A 192.0.2.10
  match parse_zone_text("example.com.", zone_text) {
    Ok(zone) => {
      assert_eq(zone.default_ttl, 5400)
      match zone.lookup("www.example.com.", @types.RType::A) {
        ExactMatch(records) => assert_eq(records[0].ttl, 5400)
        _ => fail("TTL test A record was not added to the Zone")
      }
    }
    Err(error) => fail(error.message())
  }
}

///|
test "reject malformed AAAA with its source line" {
  let zone_text =
    #|$ORIGIN example.com.
    #|www IN AAAA 2001:db8::zz
  match parse_zone_text("example.com.", zone_text) {
    Ok(_) => fail("malformed AAAA address was accepted")
    Err(error) => assert_true(error.message().contains("Line 2"))
  }
}

///|
test "reject out of range MX preference instead of truncating it" {
  let zone_text =
    #|$ORIGIN example.com.
    #|@ IN MX 65536 mail
  match parse_zone_text("example.com.", zone_text) {
    Ok(_) => fail("out of range MX preference was accepted")
    Err(error) => assert_true(error.message().contains("Line 2"))
  }
}

///|
test "reject malformed SOA integers instead of substituting defaults" {
  let zone_text =
    #|$ORIGIN example.com.
    #|@ IN SOA ns hostmaster bad-serial 7200 3600 1209600 3600
  match parse_zone_text("example.com.", zone_text) {
    Ok(_) => fail("malformed SOA serial was accepted")
    Err(error) => assert_true(error.message().contains("Line 2"))
  }
}

///|
test "reject a record with no type and report its source line" {
  let zone_text =
    #|$ORIGIN example.com.
    #|www IN
  match parse_zone_text("example.com.", zone_text) {
    Ok(_) => fail("record without a type was silently ignored")
    Err(error) => assert_true(error.message().contains("Line 2"))
  }
}

///|
test "reject TTL overflow and out of range SRV values" {
  let overflowing_ttl =
    #|$TTL 4294967296
    #|@ IN NS ns
  assert_true(parse_zone_text("example.com.", overflowing_ttl) is Err(_))

  let overflowing_srv =
    #|_sip._tcp IN SRV 65536 2 5060 server
  match parse_zone_text("example.com.", overflowing_srv) {
    Ok(_) => fail("out of range SRV priority was accepted")
    Err(error) => assert_true(error.message().contains("Line 1"))
  }
}

///|
test "preserve semicolons inside quoted TXT character strings" {
  let zone_text =
    #|@ IN TXT "first;still-first" "second"
  match parse_zone_text("example.com.", zone_text) {
    Ok(zone) =>
      match zone.lookup("example.com.", @types.RType::TXT) {
        ExactMatch(records) =>
          match records[0].rdata {
            @types.RData::TXT(chunks) => {
              assert_eq(chunks[0], "first;still-first")
              assert_eq(chunks[1], "second")
            }
            _ => fail("TXT RDATA was not parsed")
          }
        _ => fail("quoted TXT record was not added")
      }
    Err(error) => fail(error.message())
  }
}

///|
test "reject a TXT record without character strings" {
  match parse_zone_text("example.com.", "@ IN TXT\n") {
    Ok(_) => fail("TXT record without character strings was accepted")
    Err(error) => assert_true(error.message().contains("Line 1"))
  }
}

///|
test "enforce TXT character-string and RDATA wire octet limits" {
  let max_chunk = StringBuilder()
  let too_long_chunk = StringBuilder()
  for i = 0; i < 255; i = i + 1 {
    max_chunk.write_char('x')
  }
  for i = 0; i < 256; i = i + 1 {
    too_long_chunk.write_char('y')
  }
  assert_true(
    parse_zone_text(
      "example.com.",
      "@ IN TXT \"" + max_chunk.to_string() + "\"\n",
    )
    is Ok(_),
  )

  match
    parse_zone_text(
      "example.com.",
      "@ IN TXT \"" + too_long_chunk.to_string() + "\"\n",
    ) {
    Ok(_) => fail("TXT character-string longer than 255 octets was accepted")
    Err(error) => assert_true(error.message().contains("Line 1"))
  }

  let chunk = max_chunk.to_string()[:255].to_owned()
  let oversized_rdata = StringBuilder()
  oversized_rdata.write_string("@ IN TXT")
  for i = 0; i < 256; i = i + 1 {
    oversized_rdata.write_string(" \"")
    oversized_rdata.write_string(chunk)
    oversized_rdata.write_char('\"')
  }
  oversized_rdata.write_char('\n')
  match parse_zone_text("example.com.", oversized_rdata.to_string()) {
    Ok(_) => fail("TXT RDATA longer than 65535 octets was accepted")
    Err(error) => assert_true(error.message().contains("Line 1"))
  }
}

///|
test "enforce CAA total RDATA wire octet limit" {
  let oversized_value = StringBuilder()
  for i = 0; i < 65529; i = i + 1 {
    oversized_value.write_char('v')
  }
  match
    parse_zone_text(
      "example.com.",
      "@ IN CAA 0 issue \"" + oversized_value.to_string() + "\"\n",
    ) {
    Ok(_) => fail("CAA RDATA longer than 65535 octets was accepted")
    Err(error) => assert_true(error.message().contains("Line 1"))
  }
}

///|
test "count non-ASCII TXT and CAA lengths as UTF-8 octets" {
  let oversized_txt_chunk = StringBuilder()
  let oversized_caa_value = StringBuilder()
  for i = 0; i < 128; i = i + 1 {
    oversized_txt_chunk.write_char('é')
  }
  for i = 0; i < 32767; i = i + 1 {
    oversized_caa_value.write_char('é')
  }
  assert_true(
    parse_zone_text(
      "example.com.",
      "@ IN TXT \"" + oversized_txt_chunk.to_string() + "\"\n",
    )
    is Err(_),
  )
  assert_true(
    parse_zone_text(
      "example.com.",
      "@ IN CAA 0 issue \"" + oversized_caa_value.to_string() + "\"\n",
    )
    is Err(_),
  )
}
