// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Safely truncate a DNS response message to fit within max_size octets (RFC 1035 Section 4.1.1, RFC 6891)
pub fn truncate_response(
  resp : @types.Message,
  max_size : Int
) -> Bytes {
  let initial_bytes = @codec.encode_message(resp)
  if initial_bytes.length() <= max_size {
    return initial_bytes
  }

  // Set Truncation (TC) flag
  resp.header.tc = true

  // Preserve OPT pseudo-record if present
  let opt_rec : Option[@types.Record] = match find_opt_record(resp) {
    Some(opt) => Some(opt.to_record())
    None => None
  }

  // Step 1: Strip non-OPT additional records
  resp.additionals.clear()
  match opt_rec {
    Some(opt) => resp.additionals.push(opt)
    None => ()
  }
  resp.sync_counts()

  let bytes_after_add = @codec.encode_message(resp)
  if bytes_after_add.length() <= max_size {
    return bytes_after_add
  }

  // Step 2: Strip authority records
  resp.authorities.clear()
  resp.sync_counts()

  let bytes_after_auth = @codec.encode_message(resp)
  if bytes_after_auth.length() <= max_size {
    return bytes_after_auth
  }

  // Step 3: Gradually trim answers from the end until under max_size limit
  while resp.answers.length() > 0 {
    let _ = resp.answers.pop()
    resp.sync_counts()
    let current_bytes = @codec.encode_message(resp)
    if current_bytes.length() <= max_size {
      return current_bytes
    }
  }

  // Even if answers are completely stripped, return the minimal TC=1 header + question
  @codec.encode_message(resp)
}
