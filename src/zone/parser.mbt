// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
priv struct ZoneLogicalRecord {
  tokens : Array[String]
  start_line : Int
  owner_omitted : Bool
}

///|
/// Tokenize a logical record while preserving quoted strings (e.g. "v=spf1 ...")
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

///|
/// Split Zone input into logical records while tracking source lines and owner indentation
fn scan_logical_records(
  text : String,
) -> Result[Array[ZoneLogicalRecord], @types.DnsError] {
  let lines : Array[String] = []
  let mut line_buf = StringBuilder()
  for i = 0; i < text.length(); i = i + 1 {
    let ch = text[i].to_int()
    if ch == 10 {
      lines.push(line_buf.to_string())
      line_buf = StringBuilder()
    } else if ch != 13 {
      line_buf.write_char(Int::unsafe_to_char(ch))
    }
  }
  if line_buf.to_string().length() > 0 || text.length() == 0 {
    lines.push(line_buf.to_string())
  }

  let records : Array[ZoneLogicalRecord] = []
  let mut logical_buf = StringBuilder()
  let mut in_quotes = false
  let mut paren_depth = 0
  let mut record_start_line = 1
  let mut record_owner_omitted = false
  let mut has_record_content = false

  for line_idx = 0; line_idx < lines.length(); line_idx = line_idx + 1 {
    let line = lines[line_idx]
    let mut line_has_content = false
    let mut line_has_leading_space = false
    let mut i = 0
    while i < line.length() {
      let ch = line[i].to_int()
      if ch == 59 && !in_quotes { // ';' starts a comment outside quotes
        break
      }

      if ch == 32 || ch == 9 {
        if !line_has_content {
          line_has_leading_space = true
        }
        if has_record_content {
          logical_buf.write_char(' ')
        }
        i = i + 1
        continue
      }

      if !has_record_content {
        record_start_line = line_idx + 1
        record_owner_omitted = line_has_leading_space
        has_record_content = true
      }
      line_has_content = true

      if ch == 34 { // '"'
        in_quotes = !in_quotes
        logical_buf.write_char(Int::unsafe_to_char(ch))
      } else if !in_quotes && ch == 40 { // '('
        paren_depth = paren_depth + 1
        logical_buf.write_char(' ')
      } else if !in_quotes && ch == 41 { // ')'
        if paren_depth == 0 {
          return Err(
            @types.ProtocolError(
              "Line " +
              (line_idx + 1).to_string() +
              ": unmatched closing parenthesis",
            ),
          )
        }
        paren_depth = paren_depth - 1
        logical_buf.write_char(' ')
      } else {
        logical_buf.write_char(Int::unsafe_to_char(ch))
      }
      i = i + 1
    }

    if in_quotes {
      return Err(
        @types.ProtocolError(
          "Line " +
          record_start_line.to_string() +
          ": unterminated quoted string",
        ),
      )
    }

    if paren_depth == 0 {
      let tokens = tokenize_line(logical_buf.to_string())
      if tokens.length() > 0 {
        records.push({
          tokens,
          start_line: record_start_line,
          owner_omitted: record_owner_omitted,
        })
      }
      logical_buf = StringBuilder()
      has_record_content = false
      record_owner_omitted = false
    } else {
      logical_buf.write_char(' ')
    }
  }

  if paren_depth != 0 {
    return Err(
      @types.ProtocolError(
        "Line " +
        record_start_line.to_string() +
        ": unterminated parenthesized record",
      ),
    )
  }
  Ok(records)
}

///|
/// Parse an integer string into UInt
fn parse_uint(s : String) -> UInt? {
  let mut val : UInt = 0
  let trimmed = s.trim().to_owned()
  if trimmed.length() == 0 {
    return None
  }
  for i = 0; i < trimmed.length(); i = i + 1 {
    let ch = trimmed[i].to_int()
    if ch >= 48 && ch <= 57 {
      let digit = (ch - 48).reinterpret_as_uint()
      if val > 429496729 || (val == 429496729 && digit > 5) {
        return None
      }
      val = val * 10 + digit
    } else {
      return None
    }
  }
  Some(val)
}

///|
/// Parse a DNS TTL as seconds, accepting compound units such as 1h30m.
fn parse_ttl(s : String) -> UInt? {
  let text = s.trim().to_owned().to_lower()
  if text.length() == 0 {
    return None
  }
  match parse_uint(text) {
    Some(seconds) => return Some(seconds)
    None => ()
  }

  let mut total : UInt = 0
  let mut index = 0
  while index < text.length() {
    let number_start = index
    while index < text.length() {
      let ch = text[index].to_int()
      if ch >= 48 && ch <= 57 {
        index = index + 1
      } else {
        break
      }
    }
    if index == number_start || index >= text.length() {
      return None
    }
    let amount = match parse_uint(text[number_start:index].to_owned()) {
      Some(value) => value
      None => return None
    }
    let factor : UInt = match text[index].to_int() {
      119 => 604800 // w
      100 => 86400 // d
      104 => 3600 // h
      109 => 60 // m
      115 => 1 // s
      _ => return None
    }
    if amount > 4294967295 / factor {
      return None
    }
    let seconds = amount * factor
    if total > 4294967295 - seconds {
      return None
    }
    total = total + seconds
    index = index + 1
  }
  Some(total)
}

///|
/// Convert a decimal field to UInt16 without silently truncating it.
fn parse_uint16(s : String) -> UInt16? {
  match parse_uint(s) {
    Some(value) if value <= 65535 => Some(value.to_uint16())
    _ => None
  }
}

///|
/// Attach a source line to an error produced while parsing one Zone record.
fn zone_line_error(line : Int, message : String) -> @types.DnsError {
  @types.ProtocolError("Line " + line.to_string() + ": " + message)
}

///|
/// Remove the presentation quotes surrounding one DNS character string.
fn unquote_token(token : String) -> String {
  if token.length() >= 2 && token.has_prefix("\"") && token.has_suffix("\"") {
    token[1:token.length() - 1].to_owned()
  } else {
    token
  }
}

///| Resolve a domain token against the current origin:

///| - '@' becomes current origin

///| - relative name 'www' becomes 'www.<origin>'

///|
/// - absolute name 'www.example.com.' remains unchanged
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

///|
/// Parse a master-file format Zone text into an in-memory Zone database (RFC 1035 Section 5)
pub fn parse_zone_text(
  initial_origin : String,
  text : String,
) -> Result[Zone, @types.DnsError] {
  let apex_origin = @domain.normalize_fqdn(initial_origin)
  let mut current_origin = apex_origin
  let mut current_ttl : UInt = 3600
  let mut last_owner = apex_origin
  let zone = Zone::new(apex_origin, current_ttl)
  let logical_records = match scan_logical_records(text) {
    Ok(records) => records
    Err(error) => return Err(error)
  }

  for logical_record in logical_records {
    let tokens = logical_record.tokens
    if tokens.length() == 0 {
      continue
    }

    // Check directives: $ORIGIN and $TTL
    let first = tokens[0].to_upper()
    if first == "$ORIGIN" {
      if tokens.length() != 2 {
        return Err(
          @types.ProtocolError(
            "Line " +
            logical_record.start_line.to_string() +
            ": $ORIGIN requires exactly one domain",
          ),
        )
      }
      current_origin = resolve_name(tokens[1], current_origin)
      continue
    }
    if first == "$TTL" {
      if tokens.length() != 2 {
        return Err(
          @types.ProtocolError(
            "Line " +
            logical_record.start_line.to_string() +
            ": $TTL requires exactly one value",
          ),
        )
      }
      match parse_ttl(tokens[1]) {
        Some(ttl) => {
          current_ttl = ttl
          zone.default_ttl = ttl
        }
        None =>
          return Err(
            @types.ProtocolError(
              "Line " +
              logical_record.start_line.to_string() +
              ": Invalid $TTL integer",
            ),
          )
      }
      continue
    }

    // Parse standard RR line: <name> [ttl] [class] <type> <rdata...>
    let mut token_pos = 0
    let owner : String = if logical_record.owner_omitted {
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
      match parse_ttl(tokens[token_pos]) {
        Some(ttl_val) => {
          row_ttl = ttl_val
          token_pos = token_pos + 1
        }
        None => ()
      }
    }

    // Optional CLASS (e.g. IN)
    let mut row_class = @types.RClass::IN
    if token_pos < tokens.length() {
      let class_token = tokens[token_pos].to_upper()
      if class_token == "IN" {
        row_class = @types.RClass::IN
        token_pos = token_pos + 1
      } else if class_token == "CH" ||
        class_token == "HS" ||
        class_token == "NONE" ||
        class_token == "ANY" ||
        class_token.has_prefix("CLASS") {
        return Err(
          zone_line_error(
            logical_record.start_line,
            "only the IN class is supported",
          ),
        )
      }
    }

    // Required TYPE
    if token_pos >= tokens.length() {
      return Err(
        zone_line_error(
          logical_record.start_line,
          "resource record is missing a type",
        ),
      )
    }
    let rtype_str = tokens[token_pos].to_upper()
    let rtype = match @types.RType::from_string(rtype_str) {
      Some(t) => t
      None =>
        return Err(
          zone_line_error(
            logical_record.start_line,
            "unsupported RR type " + rtype_str,
          ),
        )
    }
    token_pos = token_pos + 1
    let remaining = tokens.length() - token_pos

    // Parse RDATA according to type
    let rdata : @types.RData = match rtype {
      @types.RType::A => {
        if remaining != 1 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "A record requires exactly one IPv4 address",
            ),
          )
        }
        match @records.parse_ipv4(tokens[token_pos]) {
          Ok(rd) => rd
          Err(e) =>
            return Err(zone_line_error(logical_record.start_line, e.message()))
        }
      }
      @types.RType::AAAA => {
        if remaining != 1 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "AAAA record requires exactly one IPv6 address",
            ),
          )
        }
        match @records.parse_ipv6(tokens[token_pos]) {
          Ok(rd) => rd
          Err(e) =>
            return Err(zone_line_error(logical_record.start_line, e.message()))
        }
      }
      @types.RType::CNAME => {
        if remaining != 1 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "CNAME record requires exactly one target domain",
            ),
          )
        }
        let target = resolve_name(tokens[token_pos], current_origin)
        @types.RData::CNAME(target)
      }
      @types.RType::NS => {
        if remaining != 1 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "NS record requires exactly one server domain",
            ),
          )
        }
        let target = resolve_name(tokens[token_pos], current_origin)
        @types.RData::NS(target)
      }
      @types.RType::PTR => {
        if remaining != 1 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "PTR record requires exactly one target domain",
            ),
          )
        }
        @types.RData::PTR(resolve_name(tokens[token_pos], current_origin))
      }
      @types.RType::MX => {
        if remaining != 2 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "MX record requires preference and exchange",
            ),
          )
        }
        let pref = match parse_uint16(tokens[token_pos]) {
          Some(v) => v
          None =>
            return Err(
              zone_line_error(
                logical_record.start_line,
                "invalid MX preference (expected 0..65535)",
              ),
            )
        }
        let exch = resolve_name(tokens[token_pos + 1], current_origin)
        @types.RData::MX(pref, exch)
      }
      @types.RType::TXT => {
        if remaining == 0 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "TXT record requires at least one character string",
            ),
          )
        }
        let chunks : Array[String] = []
        let mut rdata_length = 0
        while token_pos < tokens.length() {
          let chunk = unquote_token(tokens[token_pos])
          let octets = @utf8.encode(chunk).length()
          if octets > 255 {
            return Err(
              zone_line_error(
                logical_record.start_line,
                "TXT character-string exceeds 255 octets",
              ),
            )
          }
          if rdata_length > 65535 - octets - 1 {
            return Err(
              zone_line_error(
                logical_record.start_line,
                "TXT RDATA exceeds 65535 octets",
              ),
            )
          }
          rdata_length = rdata_length + octets + 1
          chunks.push(chunk)
          token_pos = token_pos + 1
        }
        @types.RData::TXT(chunks)
      }
      @types.RType::SOA => {
        if remaining != 7 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "SOA record requires exactly 7 arguments",
            ),
          )
        }
        let mname = resolve_name(tokens[token_pos], current_origin)
        let rname = resolve_name(tokens[token_pos + 1], current_origin)
        let serial = match parse_uint(tokens[token_pos + 2]) {
          Some(v) => v
          None =>
            return Err(
              zone_line_error(logical_record.start_line, "invalid SOA serial"),
            )
        }
        let refresh = match parse_uint(tokens[token_pos + 3]) {
          Some(v) => v
          None =>
            return Err(
              zone_line_error(logical_record.start_line, "invalid SOA refresh"),
            )
        }
        let retry = match parse_uint(tokens[token_pos + 4]) {
          Some(v) => v
          None =>
            return Err(
              zone_line_error(logical_record.start_line, "invalid SOA retry"),
            )
        }
        let expire = match parse_uint(tokens[token_pos + 5]) {
          Some(v) => v
          None =>
            return Err(
              zone_line_error(logical_record.start_line, "invalid SOA expire"),
            )
        }
        let minimum = match parse_uint(tokens[token_pos + 6]) {
          Some(v) => v
          None =>
            return Err(
              zone_line_error(logical_record.start_line, "invalid SOA minimum"),
            )
        }
        @types.RData::SOA(mname, rname, serial, refresh, retry, expire, minimum)
      }
      @types.RType::SRV => {
        if remaining != 4 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "SRV record requires priority, weight, port, and target",
            ),
          )
        }
        let priority = match parse_uint16(tokens[token_pos]) {
          Some(value) => value
          None =>
            return Err(
              zone_line_error(
                logical_record.start_line,
                "invalid SRV priority (expected 0..65535)",
              ),
            )
        }
        let weight = match parse_uint16(tokens[token_pos + 1]) {
          Some(value) => value
          None =>
            return Err(
              zone_line_error(
                logical_record.start_line,
                "invalid SRV weight (expected 0..65535)",
              ),
            )
        }
        let port = match parse_uint16(tokens[token_pos + 2]) {
          Some(value) => value
          None =>
            return Err(
              zone_line_error(
                logical_record.start_line,
                "invalid SRV port (expected 0..65535)",
              ),
            )
        }
        @types.RData::SRV(
          priority,
          weight,
          port,
          resolve_name(tokens[token_pos + 3], current_origin),
        )
      }
      @types.RType::CAA => {
        if remaining != 3 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "CAA record requires flags, tag, and value",
            ),
          )
        }
        let flags = match parse_uint(tokens[token_pos]) {
          Some(value) if value <= 255 => value.to_byte()
          _ =>
            return Err(
              zone_line_error(
                logical_record.start_line,
                "invalid CAA flags (expected 0..255)",
              ),
            )
        }
        let tag = unquote_token(tokens[token_pos + 1])
        let value = unquote_token(tokens[token_pos + 2])
        let tag_octets = @utf8.encode(tag).length()
        let value_octets = @utf8.encode(value).length()
        if tag_octets == 0 || tag_octets > 255 {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "CAA tag must contain 1..255 octets",
            ),
          )
        }
        if value_octets > 65535 - 2 - tag_octets {
          return Err(
            zone_line_error(
              logical_record.start_line,
              "CAA RDATA exceeds 65535 octets",
            ),
          )
        }
        @types.RData::CAA(flags, tag, value)
      }
      _ =>
        return Err(
          zone_line_error(
            logical_record.start_line,
            "RR type " + rtype_str + " is not supported by the Zone parser",
          ),
        )
    }

    let record = @types.Record::new(owner, rtype, row_class, row_ttl, rdata)
    zone.add_record(record)
  }

  Ok(zone)
}
