// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "a record encode and decode roundtrip" {
  let writer = @bytes_io.ByteWriter::new()
  encode_rdata_a(writer, (192).to_byte(), (0).to_byte(), (2).to_byte(), (1).to_byte())
  let bytes = writer.to_bytes()
  assert_eq(bytes.length(), 4)

  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_rdata_a(reader, 4) {
    Ok(rdata) => match rdata {
      @types.RData::A(b0, b1, b2, b3) => {
        assert_eq(b0.to_int(), 192)
        assert_eq(b1.to_int(), 0)
        assert_eq(b2.to_int(), 2)
        assert_eq(b3.to_int(), 1)
      }
      _ => panic()
    }
    Err(_) => panic()
  }
}

test "parse ipv4 string to rdata" {
  match parse_ipv4("93.184.216.34") {
    Ok(rdata) => match rdata {
      @types.RData::A(b0, b1, b2, b3) => {
        assert_eq(b0.to_int(), 93)
        assert_eq(b1.to_int(), 184)
        assert_eq(b2.to_int(), 216)
        assert_eq(b3.to_int(), 34)
      }
      _ => panic()
    }
    Err(_) => panic()
  }

  // Invalid formats must fail
  assert_true(parse_ipv4("256.0.0.1") is Err(_))
  assert_true(parse_ipv4("1.2.3") is Err(_))
  assert_true(parse_ipv4("1.2.3.4.5") is Err(_))
  assert_true(parse_ipv4("1.2.3.a") is Err(_))
}

test "aaaa record encode and decode roundtrip" {
  let arr = FixedArray::make(16, (0).to_byte())
  arr[0] = (0x20).to_byte()
  arr[1] = (0x01).to_byte()
  arr[2] = (0x0d).to_byte()
  arr[3] = (0xb8).to_byte()
  arr[15] = (0x01).to_byte()

  let writer = @bytes_io.ByteWriter::new()
  match encode_rdata_aaaa(writer, arr) {
    Ok(_) => ()
    Err(_) => panic()
  }
  let bytes = writer.to_bytes()
  assert_eq(bytes.length(), 16)

  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_rdata_aaaa(reader, 16) {
    Ok(rdata) => match rdata {
      @types.RData::AAAA(decoded) => {
        assert_eq(decoded[0].to_int(), 0x20)
        assert_eq(decoded[1].to_int(), 0x01)
        assert_eq(decoded[2].to_int(), 0x0d)
        assert_eq(decoded[3].to_int(), 0xb8)
        assert_eq(decoded[15].to_int(), 0x01)
      }
      _ => panic()
    }
    Err(_) => panic()
  }

  // Invalid length must fail
  let reader2 = @bytes_io.ByteReader::new(bytes)
  assert_true(decode_rdata_aaaa(reader2, 15) is Err(_))
}

test "cname and ns record roundtrip" {
  let writer = @bytes_io.ByteWriter::new()
  match encode_rdata_cname(writer, "canonical.example.com.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_rdata_cname(reader) {
    Ok(rdata) => match rdata {
      @types.RData::CNAME(target) => assert_eq(target, "canonical.example.com.")
      _ => panic()
    }
    Err(_) => panic()
  }

  let ns_writer = @bytes_io.ByteWriter::new()
  match encode_rdata_ns(ns_writer, "ns1.example.org.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let ns_bytes = ns_writer.to_bytes()
  let ns_reader = @bytes_io.ByteReader::new(ns_bytes)
  match decode_rdata_ns(ns_reader) {
    Ok(rdata) => match rdata {
      @types.RData::NS(nsdname) => assert_eq(nsdname, "ns1.example.org.")
      _ => panic()
    }
    Err(_) => panic()
  }
}
