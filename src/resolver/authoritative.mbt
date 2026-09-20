// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Find any EDNS0 OPT pseudo-record in a message's additional section
pub fn find_opt_record(msg : @types.Message) -> Option[@records.OptRecord] {
  for i = 0; i < msg.additionals.length(); i = i + 1 {
    let rec = msg.additionals[i]
    if rec.rtype == @types.RType::OPT {
      match rec.rdata {
        @types.RData::OPT(udp_sz, ext_rc, ver, do_fl, data) =>
          return Some({
            udp_payload_size: udp_sz,
            extended_rcode: ext_rc,
            version: ver,
            do_flag: do_fl,
            data,
          })
        _ => ()
      }
    }
  }
  None
}

///| Pure-function Authoritative Response Builder (RFC 1034 / RFC 1035 / RFC 2181 / RFC 6891)
pub fn build_response(
  query : @types.Message,
  zone : @zone.Zone
) -> @types.Message {
  // Step 1: Format check
  if query.questions.length() == 0 {
    let resp = @types.Message::new_response(query, false, @types.RCode::FormErr)
    resp.sync_counts()
    return resp
  }

  // Step 2: Opcode check (only standard queries supported in authoritative mode)
  if query.header.opcode != @types.OpCode::Query {
    let resp = @types.Message::new_response(query, false, @types.RCode::NotImp)
    resp.sync_counts()
    return resp
  }

  let client_opt = find_opt_record(query)
  let q = query.questions[0]
  let resp = @types.Message::new_response(query, true, @types.RCode::NoError)

  // Step 3: Zone lookup
  let lookup_res = zone.lookup(q.name, q.qtype)

  match lookup_res {
    @zone.LookupResult::NotAuthoritative => {
      resp.header.aa = false
      resp.header.rcode = @types.RCode::Refused
    }
    @zone.LookupResult::ExactMatch(recs) => {
      resp.header.aa = true
      for i = 0; i < recs.length(); i = i + 1 {
        resp.add_answer(recs[i])
      }
      append_glue_records(resp, zone)
    }
    @zone.LookupResult::WildcardMatch(recs) => {
      resp.header.aa = true
      for i = 0; i < recs.length(); i = i + 1 {
        resp.add_answer(recs[i])
      }
      append_glue_records(resp, zone)
    }
    @zone.LookupResult::CNameMatch(cname_rec, target) => {
      resp.header.aa = true
      resp.add_answer(cname_rec)
      // Recursively chase CNAME chain within zone (depth limit = 8)
      chase_cname(resp, zone, target, q.qtype, 8)
    }
    @zone.LookupResult::NoData(soa_rec) => {
      resp.header.aa = true
      resp.header.rcode = @types.RCode::NoError
      resp.add_authority(soa_rec)
    }
    @zone.LookupResult::NxDomain(soa_rec) => {
      resp.header.aa = true
      resp.header.rcode = @types.RCode::NXDomain
      resp.add_authority(soa_rec)
    }
  }

  // Step 4: Handle EDNS0 negotiation if client provided OPT record
  match client_opt {
    Some(copt) => {
      let server_opt = @records.OptRecord::new(1232, copt.do_flag)
      resp.add_additional(server_opt.to_record())
    }
    None => ()
  }

  resp.sync_counts()
  resp
}

///| Chase CNAME aliases internally within the zone up to max_depth
fn chase_cname(
  resp : @types.Message,
  zone : @zone.Zone,
  target : String,
  target_qtype : @types.RType,
  depth : Int
) -> Unit {
  if depth <= 0 {
    return
  }
  match zone.lookup(target, target_qtype) {
    @zone.LookupResult::ExactMatch(recs) => {
      for i = 0; i < recs.length(); i = i + 1 {
        resp.add_answer(recs[i])
      }
    }
    @zone.LookupResult::CNameMatch(next_cname, next_target) => {
      resp.add_answer(next_cname)
      chase_cname(resp, zone, next_target, target_qtype, depth - 1)
    }
    _ => ()
  }
}

///| Add glue IP records to the additional section for NS or MX target servers in zone
fn append_glue_records(
  resp : @types.Message,
  zone : @zone.Zone
) -> Unit {
  for i = 0; i < resp.answers.length(); i = i + 1 {
    let rec = resp.answers[i]
    let server_name : Option[String] = match rec.rdata {
      @types.RData::NS(name) => Some(name)
      @types.RData::MX(_, exch) => Some(exch)
      _ => None
    }
    match server_name {
      Some(name) => {
        match zone.lookup(name, @types.RType::A) {
          @zone.LookupResult::ExactMatch(glue_a) => {
            for j = 0; j < glue_a.length(); j = j + 1 {
              resp.add_additional(glue_a[j])
            }
          }
          _ => ()
        }
      }
      None => ()
    }
  }
}
