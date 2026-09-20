// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

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
