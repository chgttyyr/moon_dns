// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "zone lookup exact match and case insensitive" {
  let zone = Zone::new("example.com.", 300)
  let rec_a = @types.Record::new(
    "www.example.com.",
    @types.RType::A,
    @types.RClass::IN,
    300,
    @types.RData::A((93).to_byte(), (184).to_byte(), (216).to_byte(), (34).to_byte())
  )
  zone.add_record(rec_a)

  // Query with exact case
  match zone.lookup("www.example.com.", @types.RType::A) {
    ExactMatch(recs) => {
      assert_eq(recs.length(), 1)
      assert_eq(recs[0].name, "www.example.com.")
    }
    _ => panic()
  }

  // Query with UPPERCASE
  match zone.lookup("WWW.EXAMPLE.COM", @types.RType::A) {
    ExactMatch(recs) => {
      assert_eq(recs.length(), 1)
      assert_eq(recs[0].name, "www.example.com.")
    }
    _ => panic()
  }
}

test "zone lookup cname alias" {
  let zone = Zone::new("example.com.", 300)
  let cname_rec = @types.Record::new(
    "blog.example.com.",
    @types.RType::CNAME,
    @types.RClass::IN,
    300,
    @types.RData::CNAME("lb.example.com.")
  )
  zone.add_record(cname_rec)

  match zone.lookup("blog.example.com.", @types.RType::A) {
    CNameMatch(rec, target) => {
      assert_eq(rec.name, "blog.example.com.")
      assert_eq(target, "lb.example.com.")
    }
    _ => panic()
  }
}

test "zone lookup wildcard synthesis" {
  let zone = Zone::new("example.com.", 300)
  let wildcard_rec = @types.Record::new(
    "*.example.com.",
    @types.RType::A,
    @types.RClass::IN,
    300,
    @types.RData::A((10).to_byte(), (0).to_byte(), (0).to_byte(), (1).to_byte())
  )
  zone.add_record(wildcard_rec)

  // Subdomain matching wildcard
  match zone.lookup("login.example.com.", @types.RType::A) {
    WildcardMatch(recs) => {
      assert_eq(recs.length(), 1)
      // Synthesized record name should match the queried name
      assert_eq(recs[0].name, "login.example.com.")
    }
    _ => panic()
  }
}

test "zone lookup nodata and nxdomain" {
  let zone = Zone::new("example.com.", 300)
  let rec_a = @types.Record::new(
    "app.example.com.",
    @types.RType::A,
    @types.RClass::IN,
    300,
    @types.RData::A((1).to_byte(), (2).to_byte(), (3).to_byte(), (4).to_byte())
  )
  zone.add_record(rec_a)

  // 1. Name exists (app.example.com) but queried for MX -> NODATA
  match zone.lookup("app.example.com.", @types.RType::MX) {
    NoData(soa) => {
      assert_eq(soa.rtype, @types.RType::SOA)
      assert_eq(soa.name, "example.com.")
    }
    _ => panic()
  }

  // 2. Name does not exist -> NXDOMAIN
  match zone.lookup("nonexistent.example.com.", @types.RType::A) {
    NxDomain(soa) => {
      assert_eq(soa.rtype, @types.RType::SOA)
      assert_eq(soa.name, "example.com.")
    }
    _ => panic()
  }

  // 3. Out of zone origin -> NotAuthoritative
  match zone.lookup("example.org.", @types.RType::A) {
    NotAuthoritative => ()
    _ => panic()
  }
}
