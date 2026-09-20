// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "opt record ttl packing and unpacking" {
  let opt = OptRecord::new(1232, true)
  assert_eq(opt.udp_payload_size, 1232)
  assert_eq(opt.do_flag, true)

  let packed_ttl = opt.pack_ttl()
  // With do_flag = true, bit 15 (0x8000) should be set
  assert_eq(packed_ttl, 0x00008000)

  let unpacked = OptRecord::unpack(1232, packed_ttl, Bytes::from_array([]))
  assert_eq(unpacked.udp_payload_size, 1232)
  assert_eq(unpacked.do_flag, true)
  assert_eq(unpacked.extended_rcode.to_int(), 0)
  assert_eq(unpacked.version.to_int(), 0)

  // Test with extended rcode = BadVers (16)
  let opt2 : OptRecord = {
    udp_payload_size: 4096,
    extended_rcode: (16).to_byte(),
    version: (1).to_byte(),
    do_flag: false,
    data: Bytes::from_array([(1).to_byte(), (2).to_byte()]),
  }
  let packed2 = opt2.pack_ttl()
  let unpacked2 = OptRecord::unpack(4096, packed2, Bytes::from_array([(1).to_byte(), (2).to_byte()]))
  assert_eq(unpacked2.udp_payload_size, 4096)
  assert_eq(unpacked2.extended_rcode.to_int(), 16)
  assert_eq(unpacked2.version.to_int(), 1)
  assert_eq(unpacked2.do_flag, false)
  assert_eq(unpacked2.data.length(), 2)
}

test "opt to record conversion" {
  let opt = OptRecord::new(1472, false)
  let rec = opt.to_record()
  assert_eq(rec.name, ".")
  assert_eq(rec.rtype, @types.RType::OPT)
  assert_eq(rec.ttl, 0)
}
