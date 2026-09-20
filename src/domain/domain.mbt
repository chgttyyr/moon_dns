// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Convert an ASCII code point to lowercase
pub fn code_to_lower(code : Int) -> Int {
  if code >= 65 && code <= 90 {
    code + 32
  } else {
    code
  }
}

///| Normalize a domain string into a standard FQDN ending with a trailing dot
pub fn normalize_fqdn(raw : String) -> String {
  let trimmed = raw.trim().to_owned()
  if trimmed.length() == 0 || trimmed == "." {
    return "."
  }
  if trimmed.has_suffix(".") {
    trimmed
  } else {
    trimmed + "."
  }
}

///| Compare two domain names case-insensitively according to RFC 1035 rules
pub fn domain_equal(a : String, b : String) -> Bool {
  let na = normalize_fqdn(a)
  let nb = normalize_fqdn(b)
  if na.length() != nb.length() {
    return false
  }
  for i = 0; i < na.length(); i = i + 1 {
    let ca = code_to_lower(na[i].to_int())
    let cb = code_to_lower(nb[i].to_int())
    if ca != cb {
      return false
    }
  }
  true
}

///| Split a domain name into its individual label components (without dots)
pub fn split_labels(domain : String) -> Array[String] {
  let norm = normalize_fqdn(domain)
  if norm == "." {
    return []
  }
  // Strip trailing dot
  let without_dot = norm[:norm.length() - 1].to_owned()
  let result : Array[String] = []
  let mut current = StringBuilder()
  for i = 0; i < without_dot.length(); i = i + 1 {
    let ch = without_dot[i].to_int()
    if ch == 46 { // '.' is ASCII 46
      result.push(current.to_string())
      current = StringBuilder()
    } else {
      current.write_char(Int::unsafe_to_char(ch))
    }
  }
  result.push(current.to_string())
  result
}

///| Check if candidate is a subdomain of (or equal to) parent domain
pub fn is_subdomain_of(candidate : String, parent : String) -> Bool {
  let cand_labels = split_labels(candidate)
  let parent_labels = split_labels(parent)
  if cand_labels.length() < parent_labels.length() {
    return false
  }
  let offset = cand_labels.length() - parent_labels.length()
  for i = 0; i < parent_labels.length(); i = i + 1 {
    let cl = cand_labels[offset + i]
    let pl = parent_labels[i]
    if !domain_equal(cl, pl) {
      return false
    }
  }
  true
}

///| Encode a domain into length-prefixed uncompressed wire format labels
pub fn encode_domain_labels(
  writer : @bytes_io.ByteWriter,
  domain : String
) -> Result[Unit, @types.DnsError] {
  let norm = normalize_fqdn(domain)
  if norm == "." {
    writer.write_byte((0).to_byte())
    return Ok(())
  }
  let labels = split_labels(norm)
  for i = 0; i < labels.length(); i = i + 1 {
    let label = labels[i]
    let len = label.length()
    if len == 0 {
      return Err(@types.MalformedLabel("Empty label detected in domain: " + domain))
    }
    if len > 63 {
      return Err(@types.MalformedLabel("Label exceeds 63 octets: " + label))
    }
    writer.write_byte(len.to_byte())
    for j = 0; j < len; j = j + 1 {
      let ch = label[j].to_int()
      writer.write_byte(ch.to_byte())
    }
  }
  // Terminating null root label
  writer.write_byte((0).to_byte())
  Ok(())
}

///| Decode length-prefixed uncompressed wire format labels into an FQDN string
pub fn decode_domain_labels(
  reader : @bytes_io.ByteReader
) -> Result[String, @types.DnsError] {
  let buf = StringBuilder()
  let mut is_first = true
  let mut total_octets = 0

  while true {
    let len_byte = match reader.read_byte() {
      Ok(b) => b
      Err(e) => return Err(e)
    }
    let len = len_byte.to_int()
    if len == 0 {
      if is_first {
        return Ok(".")
      } else {
        buf.write_char('.')
        return Ok(buf.to_string())
      }
    }
    // Check if compression pointer bits (11) are set
    if (len & 0xc0) != 0 {
      return Err(@types.MalformedLabel("Encountered compression pointer in uncompressed reader"))
    }
    if len > 63 {
      return Err(@types.MalformedLabel("Label length exceeds 63: " + len.to_string()))
    }
    total_octets = total_octets + len + 1
    if total_octets > 255 {
      return Err(@types.MalformedLabel("Domain name exceeds 255 octets limit"))
    }
    if !is_first {
      buf.write_char('.')
    }
    is_first = false
    let label_bytes = match reader.read_bytes(len) {
      Ok(bs) => bs
      Err(e) => return Err(e)
    }
    for i = 0; i < len; i = i + 1 {
      buf.write_char(Int::unsafe_to_char(label_bytes[i].to_int()))
    }
  }
  Ok(buf.to_string())
}
