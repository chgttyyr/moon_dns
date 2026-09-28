// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
fn validation_soa(name : String) -> @types.Record {
  @types.Record::new(
    name,
    @types.RType::SOA,
    @types.RClass::IN,
    3600,
    @types.RData::SOA(
      "ns1.example.com.", "hostmaster.example.com.", 1, 7200, 3600, 1209600, 3600,
    ),
  )
}

///|
fn validation_ns(name : String) -> @types.Record {
  @types.Record::new(
    name,
    @types.RType::NS,
    @types.RClass::IN,
    3600,
    @types.RData::NS("ns1.example.com."),
  )
}

///|
fn validation_has_message(errors : Array[String], text : String) -> Bool {
  for message in errors {
    if message.contains(text) {
      return true
    }
  }
  false
}

///|
test "zone validation requires one apex SOA and at least one apex NS" {
  let zone = Zone::new("example.com.", 3600)
  assert_eq(zone.validate().length(), 2)

  zone.add_record(validation_soa("example.com."))
  zone.add_record(validation_ns("example.com."))
  assert_eq(zone.validate(), [])
}

///|
test "zone validation detects duplicate apex SOA records" {
  let zone = Zone::new("example.com.", 3600)
  zone.add_record(validation_soa("example.com."))
  zone.add_record(validation_soa("example.com."))
  zone.add_record(validation_ns("example.com."))
  assert_true(validation_has_message(zone.validate(), "multiple apex SOA"))
}

///|
test "zone validation enforces label boundary and CNAME exclusivity" {
  let zone = Zone::new("example.com.", 3600)
  zone.add_record(validation_soa("example.com."))
  zone.add_record(validation_ns("example.com."))
  zone.add_record(
    @types.Record::new(
      "badexample.com.",
      @types.RType::A,
      @types.RClass::IN,
      300,
      @types.RData::A(
        (192).to_byte(),
        (0).to_byte(),
        (2).to_byte(),
        (1).to_byte(),
      ),
    ),
  )
  zone.add_record(
    @types.Record::new(
      "alias.example.com.",
      @types.RType::CNAME,
      @types.RClass::IN,
      300,
      @types.RData::CNAME("target.example.com."),
    ),
  )
  zone.add_record(
    @types.Record::new(
      "ALIAS.EXAMPLE.COM.",
      @types.RType::A,
      @types.RClass::IN,
      300,
      @types.RData::A(
        (192).to_byte(),
        (0).to_byte(),
        (2).to_byte(),
        (2).to_byte(),
      ),
    ),
  )
  let errors = zone.validate()
  assert_eq(errors.length(), 2)
  assert_true(validation_has_message(errors, "outside zone"))
  assert_true(validation_has_message(errors, "CNAME owner"))
}

///|
test "record count reports all inserted records" {
  let zone = Zone::new("example.com.", 300)
  assert_eq(zone.record_count(), 0)
  zone.add_record(validation_soa("example.com."))
  zone.add_record(validation_ns("example.com."))
  assert_eq(zone.record_count(), 2)
}
