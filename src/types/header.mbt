// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| DNS Response Codes (RFC 1035 / RFC 6891)
pub(all) enum RCode {
  NoError   // 0: No error condition
  FormErr   // 1: Format error in query
  ServFail  // 2: Server failure
  NXDomain  // 3: Non-existent domain (Name Error)
  NotImp    // 4: Not implemented
  Refused   // 5: Query refused by policy
  YXDomain  // 6: Name exists when it should not (RFC 2136)
  YXRRSet   // 7: RR set exists when it should not
  NXRRSet   // 8: RR set that should exist does not
  NotAuth   // 9: Server not authoritative for zone
  NotZone   // 10: Name not contained in zone
  BadVers   // 16: Bad EDNS version (RFC 6891)
  Unknown(UInt16)
} derive(Debug, Eq)

///| Convert RCode to wire protocol integer
pub fn RCode::to_wire(self : RCode) -> UInt16 {
  match self {
    NoError => 0
    FormErr => 1
    ServFail => 2
    NXDomain => 3
    NotImp => 4
    Refused => 5
    YXDomain => 6
    YXRRSet => 7
    NXRRSet => 8
    NotAuth => 9
    NotZone => 10
    BadVers => 16
    Unknown(code) => code
  }
}

///| Parse RCode from wire protocol integer
pub fn RCode::from_wire(code : UInt16) -> RCode {
  match code {
    0 => NoError
    1 => FormErr
    2 => ServFail
    3 => NXDomain
    4 => NotImp
    5 => Refused
    6 => YXDomain
    7 => YXRRSet
    8 => NXRRSet
    9 => NotAuth
    10 => NotZone
    16 => BadVers
    other => Unknown(other)
  }
}

///| DNS Operation Codes (RFC 1035)
pub(all) enum OpCode {
  Query   // 0: Standard query
  IQuery  // 1: Inverse query (obsolete)
  Status  // 2: Server status request
  Notify  // 4: Zone change notification (RFC 1996)
  Update  // 5: Dynamic update (RFC 2136)
  Unknown(Byte)
} derive(Debug, Eq)

///| Convert OpCode to wire protocol byte
pub fn OpCode::to_wire(self : OpCode) -> Byte {
  match self {
    Query => 0
    IQuery => 1
    Status => 2
    Notify => 4
    Update => 5
    Unknown(val) => val
  }
}

///| Parse OpCode from wire protocol byte
pub fn OpCode::from_wire(val : Byte) -> OpCode {
  match val.to_int() {
    0 => Query
    1 => IQuery
    2 => Status
    4 => Notify
    5 => Update
    _ => Unknown(val)
  }
}

///| DNS Message Header (12 bytes fixed size, RFC 1035 Section 4.1.1)
pub(all) struct Header {
  mut id : UInt16       // 16-bit identifier assigned by query generator
  mut qr : Bool         // Query (false) or Response (true)
  mut opcode : OpCode   // 4-bit operation code
  mut aa : Bool         // Authoritative Answer
  mut tc : Bool         // Truncation flag
  mut rd : Bool         // Recursion Desired
  mut ra : Bool         // Recursion Available
  mut z : Byte          // 3-bit reserved field, must be zero
  mut rcode : RCode     // 4-bit response code
  mut qdcount : UInt16  // Number of entries in Question section
  mut ancount : UInt16  // Number of Resource Records in Answer section
  mut nscount : UInt16  // Number of Resource Records in Authority section
  mut arcount : UInt16  // Number of Resource Records in Additional section
} derive(Debug, Eq)

///| Default constructor for a new DNS query header
pub fn Header::new_query(id : UInt16) -> Header {
  {
    id,
    qr: false,
    opcode: Query,
    aa: false,
    tc: false,
    rd: true,
    ra: false,
    z: 0,
    rcode: NoError,
    qdcount: 1,
    ancount: 0,
    nscount: 0,
    arcount: 0,
  }
}

///| Construct an authoritative response header responding to a query
pub fn Header::new_response(
  id : UInt16,
  aa : Bool,
  rcode : RCode,
  qdcount : UInt16,
  ancount : UInt16,
  nscount : UInt16,
  arcount : UInt16
) -> Header {
  {
    id,
    qr: true,
    opcode: Query,
    aa,
    tc: false,
    rd: false,
    ra: false,
    z: 0,
    rcode,
    qdcount,
    ancount,
    nscount,
    arcount,
  }
}
