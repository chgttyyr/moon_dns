// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| ByteWriter provides dynamic, expandable big-endian binary stream writing.
pub(all) struct ByteWriter {
  buf : Array[Byte]
} derive(Debug)

///| Create an empty ByteWriter
pub fn ByteWriter::new() -> ByteWriter {
  { buf: [] }
}

///| Current length of accumulated bytes
pub fn ByteWriter::length(self : ByteWriter) -> Int {
  self.buf.length()
}

///| Clear the internal buffer
pub fn ByteWriter::clear(self : ByteWriter) -> Unit {
  self.buf.clear()
}

///| Write a single byte
pub fn ByteWriter::write_byte(self : ByteWriter, b : Byte) -> Unit {
  self.buf.push(b)
}

///| Write a big-endian 16-bit unsigned integer
pub fn ByteWriter::write_uint16(self : ByteWriter, val : UInt16) -> Unit {
  let v = val.to_int()
  let b0 = ((v >> 8) & 0xff).to_byte()
  let b1 = (v & 0xff).to_byte()
  self.buf.push(b0)
  self.buf.push(b1)
}

///| Write a big-endian 32-bit unsigned integer
pub fn ByteWriter::write_uint32(self : ByteWriter, val : UInt) -> Unit {
  let b0 = ((val >> 24) & 0xff).to_byte()
  let b1 = ((val >> 16) & 0xff).to_byte()
  let b2 = ((val >> 8) & 0xff).to_byte()
  let b3 = (val & 0xff).to_byte()
  self.buf.push(b0)
  self.buf.push(b1)
  self.buf.push(b2)
  self.buf.push(b3)
}

///| Write an entire Bytes sequence
pub fn ByteWriter::write_bytes(self : ByteWriter, bytes : Bytes) -> Unit {
  for i = 0; i < bytes.length(); i = i + 1 {
    self.buf.push(bytes[i])
  }
}

///| Write a FixedArray of bytes
pub fn ByteWriter::write_fixed_bytes(self : ByteWriter, bytes : FixedArray[Byte]) -> Unit {
  for i = 0; i < bytes.length(); i = i + 1 {
    self.buf.push(bytes[i])
  }
}

///| Overwrite a 16-bit unsigned integer at a previously written position (patching)
pub fn ByteWriter::patch_uint16(
  self : ByteWriter,
  pos : Int,
  val : UInt16
) -> Result[Unit, @types.DnsError] {
  if pos < 0 || pos + 2 > self.buf.length() {
    return Err(@types.BufferOverflow("Patch position out of range: " + pos.to_string()))
  }
  let v = val.to_int()
  self.buf[pos] = ((v >> 8) & 0xff).to_byte()
  self.buf[pos + 1] = (v & 0xff).to_byte()
  Ok(())
}

///| Convert internal buffer to immutable Bytes
pub fn ByteWriter::to_bytes(self : ByteWriter) -> Bytes {
  Bytes::from_array(self.buf)
}
