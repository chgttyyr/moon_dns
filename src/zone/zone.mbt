// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Result of an authoritative query lookup in a Zone database
pub(all) enum LookupResult {
  ExactMatch(Array[@types.Record])
  CNameMatch(@types.Record, String)
  WildcardMatch(Array[@types.Record])
  NoData(@types.Record)
  NxDomain(@types.Record)
  NotAuthoritative
} derive(Debug)

///| Zone database holding records for an authoritative apex origin
pub(all) struct Zone {
  origin : String
  mut default_ttl : UInt
  mut soa : Option[@types.Record]
  records : Array[@types.Record]
} derive(Debug)

///| Create an empty Zone for a given origin domain
pub fn Zone::new(origin : String, default_ttl : UInt) -> Zone {
  {
    origin: @domain.normalize_fqdn(origin),
    default_ttl,
    soa: None,
    records: [],
  }
}

///| Add a Resource Record into the zone
pub fn Zone::add_record(self : Zone, record : @types.Record) -> Unit {
  let norm_rec = @types.Record::new(
    @domain.normalize_fqdn(record.name),
    record.rtype,
    record.rclass,
    record.ttl,
    record.rdata,
  )
  if norm_rec.rtype == @types.RType::SOA {
    self.soa = Some(norm_rec)
  }
  self.records.push(norm_rec)
}

///| Get the authoritative SOA record or create a fallback default SOA
pub fn Zone::get_soa_or_fallback(self : Zone) -> @types.Record {
  match self.soa {
    Some(rec) => rec
    None => {
      let mname = "ns1." + self.origin
      let rname = "hostmaster." + self.origin
      let rdata = @types.RData::SOA(mname, rname, 1, 7200, 3600, 1209600, 3600)
      @types.Record::new(self.origin, @types.RType::SOA, @types.RClass::IN, 3600, rdata)
    }
  }
}

///| Lookup records for a given domain and QTYPE strictly implementing RFC 1034 / RFC 1035 rules
pub fn Zone::lookup(
  self : Zone,
  query_name : String,
  qtype : @types.RType
) -> LookupResult {
  let qname = @domain.normalize_fqdn(query_name)

  // Step 1: Verify authority boundary
  if !@domain.is_subdomain_of(qname, self.origin) {
    return NotAuthoritative
  }

  let soa_record = self.get_soa_or_fallback()

  // Step 2: Check for CNAME records at this exact node (CNAME takes precedence unless QTYPE=CNAME)
  if qtype != @types.RType::CNAME {
    for i = 0; i < self.records.length(); i = i + 1 {
      let rec = self.records[i]
      if @domain.domain_equal(rec.name, qname) && rec.rtype == @types.RType::CNAME {
        match rec.rdata {
          @types.RData::CNAME(target) => return CNameMatch(rec, target)
          _ => ()
        }
      }
    }
  }

  // Step 3: Exact name matching
  let matched_records : Array[@types.Record] = []
  let mut name_exists = false

  for i = 0; i < self.records.length(); i = i + 1 {
    let rec = self.records[i]
    if @domain.domain_equal(rec.name, qname) {
      name_exists = true
      if qtype == @types.RType::ANY || rec.rtype == qtype {
        matched_records.push(rec)
      }
    }
  }

  if matched_records.length() > 0 {
    return ExactMatch(matched_records)
  }

  // Step 4: Name exists but no matching QTYPE -> NODATA (RFC 1035 Section 4.3.4)
  if name_exists {
    return NoData(soa_record)
  }

  // Step 5: Wildcard synthesis (*.parent, RFC 1034 Section 4.3.3)
  let q_labels = @domain.split_labels(qname)
  let origin_labels = @domain.split_labels(self.origin)
  let depth = q_labels.length() - origin_labels.length()

  if depth > 0 {
    for i = 1; i <= depth; i = i + 1 {
      let wildcard_buf = StringBuilder()
      wildcard_buf.write_string("*.")
      for j = i; j < q_labels.length(); j = j + 1 {
        wildcard_buf.write_string(q_labels[j])
        wildcard_buf.write_char('.')
      }
      let wildcard_pattern = wildcard_buf.to_string()
      let wildcard_matches : Array[@types.Record] = []

      for k = 0; k < self.records.length(); k = k + 1 {
        let rec = self.records[k]
        if @domain.domain_equal(rec.name, wildcard_pattern) {
          if qtype == @types.RType::ANY || rec.rtype == qtype {
            // Synthesize record with query_name as owner
            let synth_rec = @types.Record::new(
              qname,
              rec.rtype,
              rec.rclass,
              rec.ttl,
              rec.rdata,
            )
            wildcard_matches.push(synth_rec)
          }
        }
      }

      if wildcard_matches.length() > 0 {
        return WildcardMatch(wildcard_matches)
      }
    }
  }

  // Step 6: Neither exact name nor wildcard exists -> NXDOMAIN
  NxDomain(soa_record)
}
