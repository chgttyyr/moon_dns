// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| ByteReader provides safe, bounds-checked big-endian binary stream reading.
pub(all) struct ByteReader {
  bytes : Bytes
  mut cursor : Int
} derive(Debug)

///| Create a new ByteReader starting at position 0
pub fn ByteReader::new(bytes : Bytes) -> ByteReader {
  { bytes, cursor: 0 }
}

///| Create a ByteReader starting at a specific offset
pub fn ByteReader::from_offset(bytes : Bytes, offset : Int) -> Result[ByteReader, @types.DnsError] {
  if offset < 0 || offset > bytes.length() {
    return Err(@types.BufferUnderflow("Invalid starting offset: " + offset.to_string()))
  }
  Ok({ bytes, cursor: offset })
}

///| Number of remaining unread bytes in buffer
pub fn ByteReader::remaining(self : ByteReader) -> Int {
  self.bytes.length() - self.cursor
}

///| Check if buffer has at least n remaining bytes
pub fn ByteReader::has_remaining(self : ByteReader, n : Int) -> Bool {
  self.remaining() >= n
}

///| Current read cursor position (0-indexed)
pub fn ByteReader::position(self : ByteReader) -> Int {
  self.cursor
}

///| Total length of the underlying bytes
pub fn ByteReader::total_length(self : ByteReader) -> Int {
  self.bytes.length()
}

///| Reposition the read cursor safely
pub fn ByteReader::set_position(self : ByteReader, pos : Int) -> Result[Unit, @types.DnsError] {
  if pos < 0 || pos > self.bytes.length() {
    return Err(@types.BufferUnderflow("Position out of bounds: " + pos.to_string()))
  }
  self.cursor = pos
  Ok(())
}

///| Advance cursor by n bytes without reading
pub fn ByteReader::skip(self : ByteReader, n : Int) -> Result[Unit, @types.DnsError] {
  if n < 0 || self.cursor + n > self.bytes.length() {
    return Err(@types.BufferUnderflow("Cannot skip " + n.to_string() + " bytes"))
  }
  self.cursor = self.cursor + n
  Ok(())
}

///| Read a single byte and advance cursor
pub fn ByteReader::read_byte(self : ByteReader) -> Result[Byte, @types.DnsError] {
  if self.cursor >= self.bytes.length() {
    return Err(@types.BufferUnderflow("End of buffer reached while reading byte"))
  }
  let b = self.bytes[self.cursor]
  self.cursor = self.cursor + 1
  Ok(b)
}

///| Peek at the current byte without advancing the cursor
pub fn ByteReader::peek_byte(self : ByteReader) -> Result[Byte, @types.DnsError] {
  if self.cursor >= self.bytes.length() {
    return Err(@types.BufferUnderflow("End of buffer reached while peeking byte"))
  }
  Ok(self.bytes[self.cursor])
}

///| Read a big-endian 16-bit unsigned integer and advance cursor by 2
pub fn ByteReader::read_uint16(self : ByteReader) -> Result[UInt16, @types.DnsError] {
  if self.cursor + 2 > self.bytes.length() {
    return Err(@types.BufferUnderflow("Not enough bytes to read UInt16 at " + self.cursor.to_string()))
  }
  let b0 = self.bytes[self.cursor].to_int()
  let b1 = self.bytes[self.cursor + 1].to_int()
  self.cursor = self.cursor + 2
  let val = ((b0 << 8) | b1).to_uint16()
  Ok(val)
}

///| Read a big-endian 32-bit unsigned integer and advance cursor by 4
pub fn ByteReader::read_uint32(self : ByteReader) -> Result[UInt, @types.DnsError] {
  if self.cursor + 4 > self.bytes.length() {
    return Err(@types.BufferUnderflow("Not enough bytes to read UInt32 at " + self.cursor.to_string()))
  }
  let b0 = self.bytes[self.cursor].to_int().reinterpret_as_uint()
  let b1 = self.bytes[self.cursor + 1].to_int().reinterpret_as_uint()
  let b2 = self.bytes[self.cursor + 2].to_int().reinterpret_as_uint()
  let b3 = self.bytes[self.cursor + 3].to_int().reinterpret_as_uint()
  self.cursor = self.cursor + 4
  let val = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  Ok(val)
}

///| Read a fixed number of bytes into a new Bytes instance
pub fn ByteReader::read_bytes(self : ByteReader, len : Int) -> Result[Bytes, @types.DnsError] {
  if len < 0 || self.cursor + len > self.bytes.length() {
    return Err(@types.BufferUnderflow("Not enough bytes to read " + len.to_string() + " bytes"))
  }
  let arr : Array[Byte] = []
  for i = 0; i < len; i = i + 1 {
    arr.push(self.bytes[self.cursor + i])
  }
  self.cursor = self.cursor + len
  Ok(Bytes::from_array(arr))
}

///| Extract a subslice without moving the primary cursor
pub fn ByteReader::sub_slice(self : ByteReader, start : Int, len : Int) -> Result[Bytes, @types.DnsError] {
  if start < 0 || len < 0 || start + len > self.bytes.length() {
    return Err(@types.BufferUnderflow("Invalid slice range: start=" + start.to_string() + ", len=" + len.to_string()))
  }
  let arr : Array[Byte] = []
  for i = 0; i < len; i = i + 1 {
    arr.push(self.bytes[start + i])
  }
  Ok(Bytes::from_array(arr))
}
