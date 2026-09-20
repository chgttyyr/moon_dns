// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| Maximum allowed pointer decompression jumps to prevent recursive amplification DoS
pub const MAX_POINTER_JUMPS : Int = 128

///| Decode a compressed domain name from the stream with four-layer malicious pointer defenses.
pub fn decode_domain_compressed(
  reader : @bytes_io.ByteReader
) -> Result[String, @types.DnsError] {
  let buf = StringBuilder()
  let mut is_first_label = true
  let mut total_octets = 0
  let mut jump_count = 0
  let mut saved_resume_pos = -1

  // Set of offsets visited during pointer chasing to detect circular references
  let visited_offsets : Array[Int] = []

  let total_len = reader.total_length()

  while true {
    let current_pos = reader.position()
    let len_byte = match reader.read_byte() {
      Ok(b) => b
      Err(e) => return Err(e)
    }
    let b = len_byte.to_int()

    // Case 1: Terminating null root label
    if b == 0 {
      if is_first_label {
        buf.write_char('.')
      } else if !buf.to_string().has_suffix(".") {
        buf.write_char('.')
      }
      // If we followed pointers, restore reader cursor to right after the first pointer
      if saved_resume_pos != -1 {
        let res = reader.set_position(saved_resume_pos)
        match res {
          Ok(_) => ()
          Err(e) => return Err(e)
        }
      }
      return Ok(@domain.normalize_fqdn(buf.to_string()))
    }

    // Case 2: Compression pointer (top two bits set to 11, RFC 1035 4.1.4)
    if (b & 0xc0) == 0xc0 {
      let b1_byte = match reader.read_byte() {
        Ok(b1) => b1
        Err(_) => return Err(@types.MalformedPointer("Truncated 2-octet pointer at offset " + current_pos.to_string()))
      }
      let b1 = b1_byte.to_int()
      let target_offset = ((b & 0x3f) << 8) | b1

      // Defense Layer 1 & 3: Target must precede current pointer and be within packet bounds
      if target_offset >= current_pos {
        return Err(@types.MalformedPointer("Pointer target " + target_offset.to_string() + " points to self or forward relative to " + current_pos.to_string()))
      }
      if target_offset < 0 || target_offset >= total_len {
        return Err(@types.MalformedPointer("Pointer target " + target_offset.to_string() + " is out of packet bounds [0, " + total_len.to_string() + ")"))
      }

      // Defense Layer 4: Jump count depth limit
      jump_count = jump_count + 1
      if jump_count > MAX_POINTER_JUMPS {
        return Err(@types.MalformedPointer("Pointer chain exceeded maximum allowed jumps (" + MAX_POINTER_JUMPS.to_string() + ")"))
      }

      // Defense Layer 2: Loop detection (A -> B -> A, etc.)
      for i = 0; i < visited_offsets.length(); i = i + 1 {
        if visited_offsets[i] == target_offset {
          return Err(@types.MalformedPointer("Circular pointer loop detected targeting offset " + target_offset.to_string()))
        }
      }
      visited_offsets.push(target_offset)

      // Save position to resume once decompression finishes (only save on first jump)
      if saved_resume_pos == -1 {
        saved_resume_pos = reader.position()
      }

      // Jump to pointer target
      let jump_res = reader.set_position(target_offset)
      match jump_res {
        Ok(_) => ()
        Err(e) => return Err(e)
      }
      continue
    }

    // Case 3: Invalid indicator bits (e.g. 01 or 10)
    if (b & 0xc0) != 0 {
      return Err(@types.MalformedLabel("Invalid label length prefix flags: 0x" + b.to_string()))
    }

    // Case 4: Standard uncompressed label (1..63 octets)
    let label_len = b
    if label_len > 63 {
      return Err(@types.MalformedLabel("Label length " + label_len.to_string() + " exceeds 63 octets limit"))
    }
    total_octets = total_octets + label_len + 1
    if total_octets > 255 {
      return Err(@types.MalformedLabel("Total domain length exceeds 255 octets limit"))
    }

    if !is_first_label {
      buf.write_char('.')
    }
    is_first_label = false

    let label_bytes = match reader.read_bytes(label_len) {
      Ok(bs) => bs
      Err(e) => return Err(e)
    }
    for i = 0; i < label_len; i = i + 1 {
      buf.write_char(Int::unsafe_to_char(label_bytes[i].to_int()))
    }
  }

  Ok(buf.to_string())
}
