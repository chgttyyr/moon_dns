// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| An entry in the outbound compression dictionary mapping a domain suffix to its byte offset
pub(all) struct CompressionEntry {
  domain : String   // Normalized FQDN suffix
  offset : Int      // Absolute wire offset in the message
} derive(Debug, Eq)

///| CompressionMap maintains a dictionary of previously encoded domain suffixes during message serialization
pub(all) struct CompressionMap {
  entries : Array[CompressionEntry]
} derive(Debug)

///| Create an empty CompressionMap
pub fn CompressionMap::new() -> CompressionMap {
  { entries: [] }
}

///| Search for a matching suffix in the compression map using case-insensitive comparison
pub fn CompressionMap::find(self : CompressionMap, suffix : String) -> Option[Int] {
  for i = 0; i < self.entries.length(); i = i + 1 {
    if @domain.domain_equal(self.entries[i].domain, suffix) {
      return Some(self.entries[i].offset)
    }
  }
  None
}

///| Insert a new domain suffix and its byte offset (ignoring offsets exceeding 14 bits)
pub fn CompressionMap::insert(self : CompressionMap, domain : String, offset : Int) -> Unit {
  if offset <= 0x3fff {
    self.entries.push({ domain: @domain.normalize_fqdn(domain), offset })
  }
}

///| Reconstruct a domain suffix starting from label index k
fn build_suffix(labels : Array[String], start_idx : Int) -> String {
  let buf = StringBuilder()
  for i = start_idx; i < labels.length(); i = i + 1 {
    buf.write_string(labels[i])
    buf.write_char('.')
  }
  buf.to_string()
}

///| Encode a domain with adaptive suffix pointer compression (RFC 1035 Section 4.1.4)
pub fn encode_domain_compressed(
  writer : @bytes_io.ByteWriter,
  cmap : CompressionMap,
  domain : String
) -> Result[Unit, @types.DnsError] {
  let norm = @domain.normalize_fqdn(domain)
  if norm == "." {
    writer.write_byte((0).to_byte())
    return Ok(())
  }

  let labels = @domain.split_labels(norm)
  let mut current_idx = 0

  while current_idx < labels.length() {
    let suffix = build_suffix(labels, current_idx)
    match cmap.find(suffix) {
      Some(pointer_offset) => {
        // Suffix found in dictionary! Output 16-bit compression pointer (0xc000 | offset)
        let ptr_val = (0xc000 | (pointer_offset & 0x3fff)).to_uint16()
        writer.write_uint16(ptr_val)
        return Ok(())
      }
      None => {
        // Suffix not yet in dictionary, record current offset for future references
        let current_offset = writer.length()
        cmap.insert(suffix, current_offset)

        // Write this single label
        let label = labels[current_idx]
        let len = label.length()
        if len > 63 {
          return Err(@types.MalformedLabel("Label exceeds 63 octets: " + label))
        }
        writer.write_byte(len.to_byte())
        for j = 0; j < len; j = j + 1 {
          writer.write_byte(label[j].to_int().to_byte())
        }
        current_idx = current_idx + 1
      }
    }
  }

  // Trailing root null label if not terminated by a pointer
  writer.write_byte((0).to_byte())
  Ok(())
}
