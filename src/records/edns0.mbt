// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| High-level structured representation of an RFC 6891 EDNS0 OPT Pseudo-Record
pub(all) struct OptRecord {
  udp_payload_size : UInt16   // Carried in the RR CLASS field (e.g. 1232, 4096)
  extended_rcode : Byte       // Upper 8 bits of extended 12-bit RCODE (TTL[24..31])
  version : Byte              // EDNS version, currently 0 (TTL[16..23])
  do_flag : Bool              // DNSSEC OK flag (bit 15 of TTL, RFC 3225)
  data : Bytes                // Raw EDNS options payload
} derive(Debug, Eq)

///| Construct a standard EDNS0 OPT record with recommended 1232-byte UDP buffer size
pub fn OptRecord::new(udp_payload_size : UInt16, do_flag : Bool) -> OptRecord {
  {
    udp_payload_size,
    extended_rcode: (0).to_byte(),
    version: (0).to_byte(),
    do_flag,
    data: Bytes::from_array([]),
  }
}

///| Pack OptRecord header attributes into the standard 32-bit TTL integer
pub fn OptRecord::pack_ttl(self : OptRecord) -> UInt {
  let ext_rc = self.extended_rcode.to_int().reinterpret_as_uint()
  let ver = self.version.to_int().reinterpret_as_uint()
  let do_bit : UInt = if self.do_flag { 0x00008000 } else { 0 }
  (ext_rc << 24) | (ver << 16) | do_bit
}

///| Unpack OptRecord attributes from wire CLASS, TTL, and RDATA
pub fn OptRecord::unpack(
  rclass : UInt16,
  ttl : UInt,
  rdata_bytes : Bytes
) -> OptRecord {
  let udp_payload_size = rclass
  let extended_rcode = ((ttl >> 24) & 0xff).reinterpret_as_int().to_byte()
  let version = ((ttl >> 16) & 0xff).reinterpret_as_int().to_byte()
  let do_flag = (ttl & 0x00008000) != 0
  {
    udp_payload_size,
    extended_rcode,
    version,
    do_flag,
    data: rdata_bytes,
  }
}

///| Convert an OptRecord into a standard generic Record
pub fn OptRecord::to_record(self : OptRecord) -> @types.Record {
  let ttl = self.pack_ttl()
  let rclass = @types.RClass::from_wire(self.udp_payload_size)
  let rdata = @types.RData::OPT(
    self.udp_payload_size,
    self.extended_rcode,
    self.version,
    self.do_flag,
    self.data,
  )
  @types.Record::new(".", @types.RType::OPT, rclass, ttl, rdata)
}
