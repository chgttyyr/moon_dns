// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| DNS Resource Record Types (RFC 1035, RFC 3596, RFC 6891, RFC 6844, etc.)
pub(all) enum RType {
  A         // 1: Host IPv4 address (RFC 1035)
  NS        // 2: Authoritative name server (RFC 1035)
  CNAME     // 5: Canonical name for an alias (RFC 1035)
  SOA       // 6: Start of a zone of authority (RFC 1035)
  PTR       // 12: Domain name pointer (RFC 1035)
  MX        // 15: Mail exchange (RFC 1035)
  TXT       // 16: Text strings (RFC 1035)
  AAAA      // 28: Host IPv6 address (RFC 3596)
  SRV       // 33: Server selector (RFC 2782)
  OPT       // 41: EDNS0 option pseudo-record (RFC 6891)
  AXFR      // 252: Zone transfer query (RFC 1035)
  ANY       // 255: Request for any records (RFC 1035)
  CAA       // 257: Certification Authority Authorization (RFC 6844)
  Unknown(UInt16)
} derive(Debug, Eq)

///| Convert RType to standard wire protocol 16-bit unsigned integer
pub fn RType::to_wire(self : RType) -> UInt16 {
  match self {
    A => 1
    NS => 2
    CNAME => 5
    SOA => 6
    PTR => 12
    MX => 15
    TXT => 16
    AAAA => 28
    SRV => 33
    OPT => 41
    AXFR => 252
    ANY => 255
    CAA => 257
    Unknown(code) => code
  }
}

///| Parse RType from wire protocol 16-bit integer
pub fn RType::from_wire(code : UInt16) -> RType {
  match code {
    1 => A
    2 => NS
    5 => CNAME
    6 => SOA
    12 => PTR
    15 => MX
    16 => TXT
    28 => AAAA
    33 => SRV
    41 => OPT
    252 => AXFR
    255 => ANY
    257 => CAA
    other => Unknown(other)
  }
}

///| Convert RType to human-readable string representation
pub fn RType::to_string(self : RType) -> String {
  match self {
    A => "A"
    NS => "NS"
    CNAME => "CNAME"
    SOA => "SOA"
    PTR => "PTR"
    MX => "MX"
    TXT => "TXT"
    AAAA => "AAAA"
    SRV => "SRV"
    OPT => "OPT"
    AXFR => "AXFR"
    ANY => "ANY"
    CAA => "CAA"
    Unknown(code) => "TYPE" + code.to_string()
  }
}

///| Parse RType from uppercase string representation
pub fn RType::from_string(s : String) -> Option[RType] {
  match s {
    "A" => Some(A)
    "NS" => Some(NS)
    "CNAME" => Some(CNAME)
    "SOA" => Some(SOA)
    "PTR" => Some(PTR)
    "MX" => Some(MX)
    "TXT" => Some(TXT)
    "AAAA" => Some(AAAA)
    "SRV" => Some(SRV)
    "OPT" => Some(OPT)
    "AXFR" => Some(AXFR)
    "ANY" => Some(ANY)
    "CAA" => Some(CAA)
    _ => None
  }
}

///| DNS Record Classes (RFC 1035 Section 3.2.4)
pub(all) enum RClass {
  IN        // 1: Internet class (the ubiquitous standard)
  CS        // 2: CSNET class (obsolete)
  CH        // 3: CHAOS class
  HS        // 4: Hesiod class
  NONE      // 254: None class (RFC 2136)
  ANY       // 255: Any class
  Unknown(UInt16)
} derive(Debug, Eq)

///| Convert RClass to wire protocol 16-bit integer
pub fn RClass::to_wire(self : RClass) -> UInt16 {
  match self {
    IN => 1
    CS => 2
    CH => 3
    HS => 4
    NONE => 254
    ANY => 255
    Unknown(code) => code
  }
}

///| Parse RClass from wire protocol 16-bit integer
pub fn RClass::from_wire(code : UInt16) -> RClass {
  match code {
    1 => IN
    2 => CS
    3 => CH
    4 => HS
    254 => NONE
    255 => ANY
    other => Unknown(other)
  }
}

///| Convert RClass to human-readable string representation
pub fn RClass::to_string(self : RClass) -> String {
  match self {
    IN => "IN"
    CS => "CS"
    CH => "CH"
    HS => "HS"
    NONE => "NONE"
    ANY => "ANY"
    Unknown(code) => "CLASS" + code.to_string()
  }
}

///| DNS Question Entry (RFC 1035 Section 4.1.2)
pub(all) struct Question {
  name : String     // Domain name in FQDN string format
  qtype : RType     // Target record type requested
  qclass : RClass   // Query class (almost always IN)
} derive(Debug, Eq)

///| Create a new Question instance
pub fn Question::new(name : String, qtype : RType, qclass : RClass) -> Question {
  { name, qtype, qclass }
}
