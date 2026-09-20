// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Complete DNS Message structure (RFC 1035 Section 4.1)
pub(all) struct Message {
  header : Header
  questions : Array[Question]
  answers : Array[Record]
  authorities : Array[Record]
  additionals : Array[Record]
} derive(Debug, Eq)

///| Constructor for an empty Message with default header
pub fn Message::new() -> Message {
  {
    header: Header::new_query(0),
    questions: [],
    answers: [],
    authorities: [],
    additionals: [],
  }
}

///| Construct a standard DNS query message for a domain and type
pub fn Message::new_query(id : UInt16, name : String, qtype : RType) -> Message {
  let header = Header::new_query(id)
  let q = Question::new(name, qtype, IN)
  {
    header,
    questions: [q],
    answers: [],
    authorities: [],
    additionals: [],
  }
}

///| Construct a response message referencing an incoming query
pub fn Message::new_response(query : Message, aa : Bool, rcode : RCode) -> Message {
  let qdcount = query.questions.length().to_uint16()
  let header = Header::new_response(query.header.id, aa, rcode, qdcount, 0, 0, 0)
  // Copy recursion desired flag from query if requested
  header.rd = query.header.rd
  {
    header,
    questions: query.questions,
    answers: [],
    authorities: [],
    additionals: [],
  }
}

///| Synchronize counts in header with actual record arrays
pub fn Message::sync_counts(self : Message) -> Unit {
  self.header.qdcount = self.questions.length().to_uint16()
  self.header.ancount = self.answers.length().to_uint16()
  self.header.nscount = self.authorities.length().to_uint16()
  self.header.arcount = self.additionals.length().to_uint16()
}

///| Append an answer record
pub fn Message::add_answer(self : Message, record : Record) -> Unit {
  self.answers.push(record)
  self.header.ancount = self.answers.length().to_uint16()
}

///| Append an authority record
pub fn Message::add_authority(self : Message, record : Record) -> Unit {
  self.authorities.push(record)
  self.header.nscount = self.authorities.length().to_uint16()
}

///| Append an additional record
pub fn Message::add_additional(self : Message, record : Record) -> Unit {
  self.additionals.push(record)
  self.header.arcount = self.additionals.length().to_uint16()
}
