// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Tokenize a single line while preserving quoted strings (e.g. "v=spf1 ...")
fn tokenize_line(line : String) -> Array[String] {
  let tokens : Array[String] = []
  let mut current = StringBuilder()
  let mut in_quotes = false
  let mut i = 0

  while i < line.length() {
    let ch = line[i].to_int()
    if ch == 59 && !in_quotes { // ';' starts a comment outside quotes
      break
    }
    if ch == 34 { // '"'
      in_quotes = !in_quotes
      current.write_char(Int::unsafe_to_char(ch))
    } else if (ch == 32 || ch == 9) && !in_quotes { // Space or Tab
      if current.to_string().length() > 0 {
        tokens.push(current.to_string())
        current = StringBuilder()
      }
    } else {
      current.write_char(Int::unsafe_to_char(ch))
    }
    i = i + 1
  }

  if current.to_string().length() > 0 {
    tokens.push(current.to_string())
  }
  tokens
}

///| Parse an integer string into UInt
fn parse_uint(s : String) -> Option[UInt] {
  let mut val : UInt = 0
  let trimmed = s.trim().to_owned()
  if trimmed.length() == 0 {
    return None
  }
  for i = 0; i < trimmed.length(); i = i + 1 {
    let ch = trimmed[i].to_int()
    if ch >= 48 && ch <= 57 {
      val = val * 10 + (ch - 48).reinterpret_as_uint()
    } else {
      return None
    }
  }
  Some(val)
}

///| Resolve a domain token against the current origin:
///| - '@' becomes current origin
///| - relative name 'www' becomes 'www.<origin>'
///| - absolute name 'www.example.com.' remains unchanged
fn resolve_name(token : String, origin : String) -> String {
  let t = token.trim().to_owned()
  if t == "@" || t.length() == 0 {
    return origin
  }
  if t.has_suffix(".") {
    return t
  }
  @domain.normalize_fqdn(t + "." + origin)
}

///| Parse a master-file format Zone text into an in-memory Zone database (RFC 1035 Section 5)
pub fn parse_zone_text(
  initial_origin : String,
  text : String
) -> Result[Zone, @types.DnsError] {
  let mut current_origin = @domain.normalize_fqdn(initial_origin)
  let mut current_ttl : UInt = 3600
  let mut last_owner = current_origin
  let zone = Zone::new(current_origin, current_ttl)

  let lines : Array[String] = []
  let mut line_buf = StringBuilder()
  for i = 0; i < text.length(); i = i + 1 {
    let ch = text[i].to_int()
    if ch == 10 { // '\n'
      lines.push(line_buf.to_string())
      line_buf = StringBuilder()
    } else if ch != 13 { // skip '\r'
      line_buf.write_char(Int::unsafe_to_char(ch))
    }
  }
  if line_buf.to_string().length() > 0 {
    lines.push(line_buf.to_string())
  }

  for line_idx = 0; line_idx < lines.length(); line_idx = line_idx + 1 {
    let tokens = tokenize_line(lines[line_idx])
    if tokens.length() == 0 {
      continue
    }

    // Check directives: $ORIGIN and $TTL
    let first = tokens[0].to_upper()
    if first == "$ORIGIN" {
      if tokens.length() < 2 {
        return Err(@types.ProtocolError("Line " + (line_idx + 1).to_string() + ": $ORIGIN missing domain"))
      }
      current_origin = @domain.normalize_fqdn(tokens[1])
      zone.origin = current_origin
      continue
    }
    if first == "$TTL" {
      if tokens.length() < 2 {
        return Err(@types.ProtocolError("Line " + (line_idx + 1).to_string() + ": $TTL missing seconds"))
      }
      match parse_uint(tokens[1]) {
        Some(ttl) => {
          current_ttl = ttl
          zone.default_ttl = ttl
        }
        None => return Err(@types.ProtocolError("Line " + (line_idx + 1).to_string() + ": Invalid $TTL integer"))
      }
      continue
    }

    // Parse standard RR line: <name> [ttl] [class] <type> <rdata...>
    let mut token_pos = 0
    let owner : String = if tokens[0] == "IN" || @types.RType::from_string(tokens[0].to_upper()) != None {
      // Name omitted, reuse previous owner
      last_owner
    } else {
      let resolved = resolve_name(tokens[0], current_origin)
      last_owner = resolved
      token_pos = token_pos + 1
      resolved
    }

    // Optional TTL
    let mut row_ttl = current_ttl
    if token_pos < tokens.length() {
      match parse_uint(tokens[token_pos]) {
        Some(ttl_val) => {
          row_ttl = ttl_val
          token_pos = token_pos + 1
        }
        None => ()
      }
    }

    // Optional CLASS (e.g. IN)
    let mut row_class = @types.RClass::IN
    if token_pos < tokens.length() && tokens[token_pos].to_upper() == "IN" {
      row_class = @types.RClass::IN
      token_pos = token_pos + 1
    }

    // Required TYPE
    if token_pos >= tokens.length() {
      continue
    }
    let rtype_str = tokens[token_pos].to_upper()
    let rtype = match @types.RType::from_string(rtype_str) {
      Some(t) => t
      None => return Err(@types.UnsupportedType(0))
    }
    token_pos = token_pos + 1

    // Parse RDATA according to type
    let rdata : @types.RData = match rtype {
      @types.RType::A => {
        if token_pos >= tokens.length() {
          return Err(@types.ProtocolError("A record missing IPv4 address"))
        }
        match @records.parse_ipv4(tokens[token_pos]) {
          Ok(rd) => rd
          Err(e) => return Err(e)
        }
      }
      @types.RType::CNAME => {
        if token_pos >= tokens.length() {
          return Err(@types.ProtocolError("CNAME record missing target domain"))
        }
        let target = resolve_name(tokens[token_pos], current_origin)
        @types.RData::CNAME(target)
      }
      @types.RType::NS => {
        if token_pos >= tokens.length() {
          return Err(@types.ProtocolError("NS record missing server domain"))
        }
        let target = resolve_name(tokens[token_pos], current_origin)
        @types.RData::NS(target)
      }
      @types.RType::MX => {
        if token_pos + 1 >= tokens.length() {
          return Err(@types.ProtocolError("MX record missing preference or exchange"))
        }
        let pref_uint = match parse_uint(tokens[token_pos]) {
          Some(v) => v
          None => return Err(@types.ProtocolError("Invalid MX preference integer"))
        }
        let exch = resolve_name(tokens[token_pos + 1], current_origin)
        @types.RData::MX(pref_uint.to_uint16(), exch)
      }
      @types.RType::TXT => {
        let chunks : Array[String] = []
        while token_pos < tokens.length() {
          let mut t = tokens[token_pos]
          // Strip surrounding quotes if present
          if t.length() >= 2 && t.has_prefix("\"") && t.has_suffix("\"") {
            t = t[1:t.length() - 1].to_owned()
          }
          chunks.push(t)
          token_pos = token_pos + 1
        }
        @types.RData::TXT(chunks)
      }
      @types.RType::SOA => {
        if token_pos + 6 >= tokens.length() {
          return Err(@types.ProtocolError("SOA record requires 7 arguments"))
        }
        let mname = resolve_name(tokens[token_pos], current_origin)
        let rname = resolve_name(tokens[token_pos + 1], current_origin)
        let serial = match parse_uint(tokens[token_pos + 2]) {
          Some(v) => v
          None => 1
        }
        let refresh = match parse_uint(tokens[token_pos + 3]) {
          Some(v) => v
          None => 7200
        }
        let retry = match parse_uint(tokens[token_pos + 4]) {
          Some(v) => v
          None => 3600
        }
        let expire = match parse_uint(tokens[token_pos + 5]) {
          Some(v) => v
          None => 1209600
        }
        let minimum = match parse_uint(tokens[token_pos + 6]) {
          Some(v) => v
          None => 3600
        }
        @types.RData::SOA(mname, rname, serial, refresh, retry, expire, minimum)
      }
      _ => @types.RData::Raw(Bytes::from_array([]))
    }

    let record = @types.Record::new(owner, rtype, row_class, row_ttl, rdata)
    zone.add_record(record)
  }

  Ok(zone)
}
