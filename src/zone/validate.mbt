// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Validate apex records, owner boundaries, and CNAME exclusivity.

///|
/// The returned diagnostics are stable and follow record insertion order.
pub fn Zone::validate(self : Zone) -> Array[String] {
  let errors : Array[String] = []
  let origin = @domain.normalize_fqdn(self.origin)
  let mut apex_soa_count = 0
  let mut has_apex_ns = false

  for record in self.records {
    let owner = @domain.normalize_fqdn(record.name)
    if !@domain.is_subdomain_of(owner, origin) {
      errors.push("owner " + owner + " is outside zone " + origin)
    }
    if record.rtype == @types.RType::SOA && @domain.domain_equal(owner, origin) {
      apex_soa_count = apex_soa_count + 1
    }
    if record.rtype == @types.RType::NS && @domain.domain_equal(owner, origin) {
      has_apex_ns = true
    }
  }

  if apex_soa_count == 0 {
    errors.push("missing apex SOA for " + origin)
  } else if apex_soa_count > 1 {
    errors.push(
      "multiple apex SOA records for " +
      origin +
      " (found " +
      apex_soa_count.to_string() +
      ")",
    )
  }
  if !has_apex_ns {
    errors.push("missing apex NS for " + origin)
  }

  for i = 0; i < self.records.length(); i = i + 1 {
    let record = self.records[i]
    if record.rtype == @types.RType::CNAME {
      let owner = @domain.normalize_fqdn(record.name)
      let mut seen_cname = false
      for prior = 0; prior < i; prior = prior + 1 {
        if self.records[prior].rtype == @types.RType::CNAME &&
          @domain.domain_equal(self.records[prior].name, owner) {
          seen_cname = true
        }
      }
      if !seen_cname {
        let mut has_other_type = false
        for other in self.records {
          if @domain.domain_equal(other.name, owner) &&
            other.rtype != @types.RType::CNAME {
            has_other_type = true
          }
        }
        if has_other_type {
          errors.push("CNAME owner " + owner + " also has other record types")
        }
      }
    }
  }
  errors
}
