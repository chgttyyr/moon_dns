// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
/// Parse one hexadecimal IPv6 group.
fn parse_ipv6_group(text : String) -> UInt? {
  if text.length() == 0 || text.length() > 4 {
    return None
  }
  let mut value : UInt = 0
  for i = 0; i < text.length(); i = i + 1 {
    let ch = text[i].to_int()
    let digit = if ch >= 48 && ch <= 57 {
      ch - 48
    } else if ch >= 65 && ch <= 70 {
      ch - 55
    } else if ch >= 97 && ch <= 102 {
      ch - 87
    } else {
      return None
    }
    value = value * 16 + digit.reinterpret_as_uint()
  }
  Some(value)
}

///|
/// Parse a colon-separated sequence of non-empty IPv6 groups.
fn parse_ipv6_groups(text : String) -> Array[UInt]? {
  let groups : Array[UInt] = []
  if text.length() == 0 {
    return Some(groups)
  }

  let mut start = 0
  for i = 0; i <= text.length(); i = i + 1 {
    if i == text.length() || text[i].to_int() == 58 {
      if i == start {
        return None
      }
      match parse_ipv6_group(text[start:i].to_owned()) {
        Some(group) => groups.push(group)
        None => return None
      }
      start = i + 1
    }
  }
  Some(groups)
}

///|
/// Parse an IPv6 presentation address into its 16-byte AAAA payload.
pub fn parse_ipv6(ip_str : String) -> Result[@types.RData, @types.DnsError] {
  let text = ip_str.trim().to_owned()
  if text.length() == 0 || text.contains(".") {
    return Err(@types.InvalidCharacter("Invalid IPv6 address: " + ip_str))
  }

  let mut compression = -1
  let mut i = 0
  while i + 1 < text.length() {
    if text[i].to_int() == 58 && text[i + 1].to_int() == 58 {
      if compression >= 0 {
        return Err(
          @types.InvalidCharacter(
            "IPv6 address has multiple :: markers: " + ip_str,
          ),
        )
      }
      compression = i
      i = i + 2
    } else {
      i = i + 1
    }
  }

  let groups : Array[UInt] = []
  if compression < 0 {
    match parse_ipv6_groups(text) {
      Some(parsed) => {
        if parsed.length() != 8 {
          return Err(
            @types.InvalidLength(
              "IPv6 address must contain 8 groups without ::",
            ),
          )
        }
        for group in parsed {
          groups.push(group)
        }
      }
      None =>
        return Err(@types.InvalidCharacter("Invalid IPv6 address: " + ip_str))
    }
  } else {
    let left_text = text[0:compression].to_owned()
    let right_text = text[compression + 2:text.length()].to_owned()
    let left = match parse_ipv6_groups(left_text) {
      Some(parsed) => parsed
      None =>
        return Err(@types.InvalidCharacter("Invalid IPv6 address: " + ip_str))
    }
    let right = match parse_ipv6_groups(right_text) {
      Some(parsed) => parsed
      None =>
        return Err(@types.InvalidCharacter("Invalid IPv6 address: " + ip_str))
    }
    if left.length() + right.length() >= 8 {
      return Err(
        @types.InvalidLength("IPv6 :: must compress at least one group"),
      )
    }
    for group in left {
      groups.push(group)
    }
    for fill_index = 0
        fill_index < 8 - left.length() - right.length()
        fill_index = fill_index + 1 {
      groups.push(0)
    }
    for group in right {
      groups.push(group)
    }
  }

  let bytes = FixedArray::make(16, (0).to_byte())
  for index = 0; index < 8; index = index + 1 {
    bytes[index * 2] = (groups[index] / 256).to_byte()
    bytes[index * 2 + 1] = (groups[index] % 256).to_byte()
  }
  Ok(@types.RData::AAAA(bytes))
}
