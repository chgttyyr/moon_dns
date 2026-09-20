// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| RData payload variants corresponding to each supported DNS RR type
pub(all) enum RData {
  A(Byte, Byte, Byte, Byte)
  AAAA(FixedArray[Byte])
  CNAME(String)
  NS(String)
  PTR(String)
  MX(UInt16, String)
  TXT(Array[String])
  SOA(String, String, UInt, UInt, UInt, UInt, UInt)
  SRV(UInt16, UInt16, UInt16, String)
  CAA(Byte, String, String)
  OPT(UInt16, Byte, Byte, Bool, Bytes)
  Raw(Bytes)
} derive(Debug, Eq)

///| Returns the corresponding RType for this RData instance
pub fn RData::rtype(self : RData) -> RType {
  match self {
    A(_) => A
    AAAA(_) => AAAA
    CNAME(_) => CNAME
    NS(_) => NS
    PTR(_) => PTR
    MX(_, _) => MX
    TXT(_) => TXT
    SOA(_, _, _, _, _, _, _) => SOA
    SRV(_, _, _, _) => SRV
    CAA(_, _, _) => CAA
    OPT(_, _, _, _, _) => OPT
    Raw(_) => Unknown(0)
  }
}

///| Helper to format IPv4 address as dotted quad
pub fn format_ipv4(b0 : Byte, b1 : Byte, b2 : Byte, b3 : Byte) -> String {
  b0.to_int().to_string() + "." +
  b1.to_int().to_string() + "." +
  b2.to_int().to_string() + "." +
  b3.to_int().to_string()
}

///| Helper to format IPv6 address as colon-hex
pub fn format_ipv6(bytes : FixedArray[Byte]) -> String {
  let buf = StringBuilder()
  for i = 0; i < 16; i = i + 2 {
    let hi = bytes[i].to_int()
    let lo = bytes[i + 1].to_int()
    let val = (hi << 8) | lo
    let hex_chars = "0123456789abcdef"
    let d0 = hex_chars[(val >> 12) & 0x0f]
    let d1 = hex_chars[(val >> 8) & 0x0f]
    let d2 = hex_chars[(val >> 4) & 0x0f]
    let d3 = hex_chars[val & 0x0f]
    let s = d0.to_string() + d1.to_string() + d2.to_string() + d3.to_string()
    buf.write_string(s)
    if i < 14 {
      buf.write_char(':')
    }
  }
  buf.to_string()
}

///| Format RData into standard master file presentation text
pub fn RData::to_presentation(self : RData) -> String {
  match self {
    A(b0, b1, b2, b3) => format_ipv4(b0, b1, b2, b3)
    AAAA(arr) => format_ipv6(arr)
    CNAME(name) => name
    NS(name) => name
    PTR(name) => name
    MX(pref, exch) => pref.to_string() + " " + exch
    TXT(chunks) => {
      let buf = StringBuilder()
      for i = 0; i < chunks.length(); i = i + 1 {
        if i > 0 {
          buf.write_char(' ')
        }
        buf.write_char('"')
        buf.write_string(chunks[i])
        buf.write_char('"')
      }
      buf.to_string()
    }
    SOA(mname, rname, serial, refresh, retry, expire, min) =>
      mname + " " + rname + " " + serial.to_string() + " " +
      refresh.to_string() + " " + retry.to_string() + " " +
      expire.to_string() + " " + min.to_string()
    SRV(prio, weight, port, target) =>
      prio.to_string() + " " + weight.to_string() + " " +
      port.to_string() + " " + target
    CAA(flags, tag, val) => flags.to_int().to_string() + " " + tag + " \"" + val + "\""
    OPT(udp_size, _, _, _, _) => "EDNS0 UDP=" + udp_size.to_string()
    Raw(bytes) => "RAW[" + bytes.length().to_string() + " bytes]"
  }
}

///| DNS Resource Record (RFC 1035 Section 4.1.3)
pub(all) struct Record {
  name : String     // Domain name owner of this record
  rtype : RType     // Record type
  rclass : RClass   // Record class (typically IN)
  ttl : UInt        // Time to live in seconds
  rdata : RData     // Type-specific payload
} derive(Debug, Eq)

///| Constructor for a standard Record
pub fn Record::new(
  name : String,
  rtype : RType,
  rclass : RClass,
  ttl : UInt,
  rdata : RData
) -> Record {
  { name, rtype, rclass, ttl, rdata }
}
