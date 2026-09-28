// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
test "mx record roundtrip" {
  let writer = @bytes_io.ByteWriter::new()
  match encode_rdata_mx(writer, 10, "mail.example.com.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_rdata_mx(reader) {
    Ok(rdata) =>
      match rdata {
        @types.RData::MX(pref, exch) => {
          assert_eq(pref, 10)
          assert_eq(exch, "mail.example.com.")
        }
        _ => panic()
      }
    Err(_) => panic()
  }
}

///|
test "txt record multi-chunk roundtrip" {
  let writer = @bytes_io.ByteWriter::new()
  let chunks = [
    "v=spf1 include:_spf.google.com ~all", "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNAD",
  ]
  match encode_rdata_txt(writer, chunks) {
    Ok(_) => ()
    Err(_) => panic()
  }
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_rdata_txt(reader, bytes.length().to_uint16()) {
    Ok(rdata) =>
      match rdata {
        @types.RData::TXT(decoded_chunks) => {
          assert_eq(decoded_chunks.length(), 2)
          assert_eq(decoded_chunks[0], "v=spf1 include:_spf.google.com ~all")
          assert_eq(
            decoded_chunks[1],
            "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNAD",
          )
        }
        _ => panic()
      }
    Err(_) => panic()
  }
}

///|
test "soa record full tuple roundtrip" {
  let writer = @bytes_io.ByteWriter::new()
  match
    encode_rdata_soa(
      writer, "ns1.example.com.", "hostmaster.example.com.", 2026092001, 7200, 3600,
      1209600, 3600,
    ) {
    Ok(_) => ()
    Err(_) => panic()
  }
  let bytes = writer.to_bytes()
  let reader = @bytes_io.ByteReader::new(bytes)
  match decode_rdata_soa(reader) {
    Ok(rdata) =>
      match rdata {
        @types.RData::SOA(mname, rname, serial, refresh, retry, expire, min) => {
          assert_eq(mname, "ns1.example.com.")
          assert_eq(rname, "hostmaster.example.com.")
          assert_eq(serial, 2026092001)
          assert_eq(refresh, 7200)
          assert_eq(retry, 3600)
          assert_eq(expire, 1209600)
          assert_eq(min, 3600)
        }
        _ => panic()
      }
    Err(_) => panic()
  }
}

///|
test "srv and caa record roundtrip" {
  let srv_writer = @bytes_io.ByteWriter::new()
  match encode_rdata_srv(srv_writer, 1, 10, 5060, "sip.example.com.") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let srv_bytes = srv_writer.to_bytes()
  let srv_reader = @bytes_io.ByteReader::new(srv_bytes)
  match decode_rdata_srv(srv_reader) {
    Ok(rdata) =>
      match rdata {
        @types.RData::SRV(prio, weight, port, target) => {
          assert_eq(prio, 1)
          assert_eq(weight, 10)
          assert_eq(port, 5060)
          assert_eq(target, "sip.example.com.")
        }
        _ => panic()
      }
    Err(_) => panic()
  }

  let caa_writer = @bytes_io.ByteWriter::new()
  match
    encode_rdata_caa(caa_writer, (0).to_byte(), "issue", "letsencrypt.org") {
    Ok(_) => ()
    Err(_) => panic()
  }
  let caa_bytes = caa_writer.to_bytes()
  let caa_reader = @bytes_io.ByteReader::new(caa_bytes)
  match decode_rdata_caa(caa_reader, caa_bytes.length().to_uint16()) {
    Ok(rdata) =>
      match rdata {
        @types.RData::CAA(flags, tag, val) => {
          assert_eq(flags.to_int(), 0)
          assert_eq(tag, "issue")
          assert_eq(val, "letsencrypt.org")
        }
        _ => panic()
      }
    Err(_) => panic()
  }
}

///|
test "TXT and CAA encoders enforce DNS RDATA octet limits" {
  let max_txt_chunk = StringBuilder()
  for i = 0; i < 255; i = i + 1 {
    max_txt_chunk.write_char('x')
  }
  let oversized_txt = StringBuilder()
  for i = 0; i < 256; i = i + 1 {
    oversized_txt.write_char('y')
  }

  let txt_writer = @bytes_io.ByteWriter::new()
  assert_true(
    encode_rdata_txt(txt_writer, [oversized_txt.to_string()]) is Err(_),
  )
  assert_eq(txt_writer.to_bytes().length(), 0)
  assert_true(
    encode_rdata_txt(txt_writer, Array::make(256, max_txt_chunk.to_string()))
    is Err(_),
  )
  assert_eq(txt_writer.to_bytes().length(), 0)

  let caa_writer = @bytes_io.ByteWriter::new()
  let oversized_value = StringBuilder()
  for i = 0; i < 65529; i = i + 1 {
    oversized_value.write_char('v')
  }
  assert_true(
    encode_rdata_caa(
      caa_writer,
      (0).to_byte(),
      "issue",
      oversized_value.to_string(),
    )
    is Err(_),
  )
  assert_eq(caa_writer.to_bytes().length(), 0)
}

///|
test "TXT and CAA encoders count UTF-8 octets" {
  let multibyte_chunk = StringBuilder()
  for i = 0; i < 128; i = i + 1 {
    multibyte_chunk.write_char('é')
  }
  let txt_writer = @bytes_io.ByteWriter::new()
  assert_true(
    encode_rdata_txt(txt_writer, [multibyte_chunk.to_string()]) is Err(_),
  )

  let caa_value = StringBuilder()
  for i = 0; i < 32767; i = i + 1 {
    caa_value.write_char('é')
  }
  let caa_writer = @bytes_io.ByteWriter::new()
  assert_true(
    encode_rdata_caa(caa_writer, (0).to_byte(), "issue", caa_value.to_string())
    is Err(_),
  )
}

///|
test "TXT and CAA preserve UTF-8 values in wire roundtrips" {
  let txt_writer = @bytes_io.ByteWriter::new()
  match encode_rdata_txt(txt_writer, ["café", "雪"]) {
    Err(error) => fail(error.message())
    Ok(_) => ()
  }
  let txt_bytes = txt_writer.to_bytes()
  match
    decode_rdata_txt(
      @bytes_io.ByteReader::new(txt_bytes),
      txt_bytes.length().to_uint16(),
    ) {
    Ok(@types.RData::TXT(chunks)) => {
      assert_eq(chunks[0], "café")
      assert_eq(chunks[1], "雪")
    }
    Ok(_) => fail("decoded TXT RDATA had the wrong type")
    Err(error) => fail(error.message())
  }

  let caa_writer = @bytes_io.ByteWriter::new()
  match encode_rdata_caa(caa_writer, (0).to_byte(), "issue", "hébergement") {
    Err(error) => fail(error.message())
    Ok(_) => ()
  }
  let caa_bytes = caa_writer.to_bytes()
  match
    decode_rdata_caa(
      @bytes_io.ByteReader::new(caa_bytes),
      caa_bytes.length().to_uint16(),
    ) {
    Ok(@types.RData::CAA(_, tag, value)) => {
      assert_eq(tag, "issue")
      assert_eq(value, "hébergement")
    }
    Ok(_) => fail("decoded CAA RDATA had the wrong type")
    Err(error) => fail(error.message())
  }
}
