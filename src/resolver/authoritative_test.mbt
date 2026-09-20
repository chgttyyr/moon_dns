// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "authoritative resolver normal match and glue records" {
  let zone = @zone.Zone::new("example.com.", 300)

  // SOA
  let soa = @types.Record::new(
    "example.com.",
    @types.RType::SOA,
    @types.RClass::IN,
    3600,
    @types.RData::SOA("ns1.example.com.", "hostmaster.example.com.", 1, 7200, 3600, 1209600, 3600)
  )
  zone.add_record(soa)

  // NS record
  let ns = @types.Record::new(
    "example.com.",
    @types.RType::NS,
    @types.RClass::IN,
    86400,
    @types.RData::NS("ns1.example.com.")
  )
  zone.add_record(ns)

  // Glue A record for ns1
  let glue_a = @types.Record::new(
    "ns1.example.com.",
    @types.RType::A,
    @types.RClass::IN,
    86400,
    @types.RData::A((192).to_byte(), (0).to_byte(), (2).to_byte(), (53).to_byte())
  )
  zone.add_record(glue_a)

  // Query NS
  let query = @types.Message::new_query(0x1111, "example.com.", @types.RType::NS)
  let resp = build_response(query, zone)

  assert_eq(resp.header.id, 0x1111)
  assert_eq(resp.header.qr, true)
  assert_eq(resp.header.aa, true)
  assert_eq(resp.header.rcode, @types.RCode::NoError)
  assert_eq(resp.answers.length(), 1)
  assert_eq(resp.answers[0].name, "example.com.")
  // Glue record should be automatically appended to additionals
  assert_eq(resp.additionals.length(), 1)
  assert_eq(resp.additionals[0].name, "ns1.example.com.")
}

test "authoritative resolver nodata semantics" {
  let zone = @zone.Zone::new("example.com.", 300)
  let soa = @types.Record::new(
    "example.com.",
    @types.RType::SOA,
    @types.RClass::IN,
    3600,
    @types.RData::SOA("ns1.example.com.", "hostmaster.example.com.", 1, 7200, 3600, 1209600, 3600)
  )
  zone.add_record(soa)

  let rec_a = @types.Record::new(
    "app.example.com.",
    @types.RType::A,
    @types.RClass::IN,
    300,
    @types.RData::A((1).to_byte(), (2).to_byte(), (3).to_byte(), (4).to_byte())
  )
  zone.add_record(rec_a)

  // Query for TXT when only A exists
  let query = @types.Message::new_query(0x2222, "app.example.com.", @types.RType::TXT)
  let resp = build_response(query, zone)

  assert_eq(resp.header.aa, true)
  assert_eq(resp.header.rcode, @types.RCode::NoError)
  assert_eq(resp.answers.length(), 0)
  // Authority section MUST carry SOA record
  assert_eq(resp.authorities.length(), 1)
  assert_eq(resp.authorities[0].rtype, @types.RType::SOA)
}

test "authoritative resolver nxdomain semantics" {
  let zone = @zone.Zone::new("example.com.", 300)
  let soa = @types.Record::new(
    "example.com.",
    @types.RType::SOA,
    @types.RClass::IN,
    3600,
    @types.RData::SOA("ns1.example.com.", "hostmaster.example.com.", 1, 7200, 3600, 1209600, 3600)
  )
  zone.add_record(soa)

  // Query nonexistent name
  let query = @types.Message::new_query(0x3333, "ghost.example.com.", @types.RType::A)
  let resp = build_response(query, zone)

  assert_eq(resp.header.aa, true)
  assert_eq(resp.header.rcode, @types.RCode::NXDomain)
  assert_eq(resp.answers.length(), 0)
  // Authority section MUST carry SOA record
  assert_eq(resp.authorities.length(), 1)
  assert_eq(resp.authorities[0].rtype, @types.RType::SOA)
}

test "authoritative resolver cname chain chasing" {
  let zone = @zone.Zone::new("example.com.", 300)
  let cname = @types.Record::new(
    "alias.example.com.",
    @types.RType::CNAME,
    @types.RClass::IN,
    300,
    @types.RData::CNAME("target.example.com.")
  )
  let target_a = @types.Record::new(
    "target.example.com.",
    @types.RType::A,
    @types.RClass::IN,
    300,
    @types.RData::A((10).to_byte(), (20).to_byte(), (30).to_byte(), (40).to_byte())
  )
  zone.add_record(cname)
  zone.add_record(target_a)

  let query = @types.Message::new_query(0x4444, "alias.example.com.", @types.RType::A)
  let resp = build_response(query, zone)

  assert_eq(resp.header.aa, true)
  assert_eq(resp.header.rcode, @types.RCode::NoError)
  // Both CNAME and final target A record should be in answers
  assert_eq(resp.answers.length(), 2)
  assert_eq(resp.answers[0].rtype, @types.RType::CNAME)
  assert_eq(resp.answers[1].rtype, @types.RType::A)
}

test "authoritative resolver edns0 opt negotiation" {
  let zone = @zone.Zone::new("example.com.", 300)
  let query = @types.Message::new_query(0x5555, "example.com.", @types.RType::SOA)
  let opt = @records.OptRecord::new(4096, true)
  query.add_additional(opt.to_record())

  let resp = build_response(query, zone)
  assert_eq(resp.additionals.length(), 1)
  assert_eq(resp.additionals[0].rtype, @types.RType::OPT)
}
