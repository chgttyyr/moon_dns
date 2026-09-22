// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

test "facade server creation and quick resolve" {
  let zone_text =
    #|$ORIGIN mycloud.io.
    #|$TTL 300
    #|@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300
    #|@ IN NS ns1
    #|ns1 IN A 192.0.2.1
    #|app IN A 10.0.0.1
    #|api IN CNAME app
  match create_server_from_zone_text("mycloud.io.", zone_text) {
    Ok(server) => {
      // 1. Resolve A record
      match quick_resolve(server, "app.mycloud.io.", @types.RType::A) {
        Ok(answers) => {
          assert_eq(answers.length(), 1)
          assert_eq(answers[0].name, "app.mycloud.io.")
        }
        Err(_) => panic()
      }

      // 2. Resolve CNAME
      match quick_resolve(server, "api.mycloud.io.", @types.RType::A) {
        Ok(answers) => {
          assert_eq(answers.length(), 2) // CNAME + target A
          assert_eq(answers[0].rtype, @types.RType::CNAME)
          assert_eq(answers[1].rtype, @types.RType::A)
        }
        Err(_) => panic()
      }
    }
    Err(_) => panic()
  }
}

test "facade hex codec and packet resolution" {
  // 1. Test hex codec roundtrip
  let raw = Bytes::from_array([ (0xDE).to_byte(), (0xAD).to_byte(), (0xBE).to_byte(), (0xEF).to_byte() ])
  let hex = bytes_to_hex(raw)
  assert_eq(hex, "deadbeef")
  let back = hex_to_bytes(hex)
  assert_eq(back.length(), 4)
  assert_eq(back[0], (0xDE).to_byte())
  assert_eq(back[3], (0xEF).to_byte())

  // 2. Test raw packet resolution
  let zone_text =
    #|$ORIGIN hexzone.org.
    #|$TTL 60
    #|@ IN SOA ns1 hostmaster 1 7200 3600 1209600 60
    #|@ IN NS ns1
    #|ns1 IN A 1.2.3.4
    #|server IN A 5.6.7.8
  match create_server_from_zone_text("hexzone.org.", zone_text) {
    Ok(server) => {
      let q = @types.Message::new_query(0x4321, "server.hexzone.org.", @types.RType::A)
      let q_bytes = @codec.encode_message(q)
      match resolve_raw_packet(server, q_bytes) {
        Ok(resp_bytes) => {
          let resp = match @codec.decode_message(resp_bytes) {
            Ok(m) => m
            Err(_) => panic()
          }
          assert_eq(resp.answers.length(), 1)
          assert_eq(resp.header.id, 0x4321)
          assert_true(resp.header.aa)
        }
        Err(_) => panic()
      }

      // 3. Test hex packet resolution
      let q_hex = bytes_to_hex(q_bytes)
      match resolve_hex_packet(server, q_hex) {
        Ok(resp_hex) => {
          assert_true(resp_hex.length() > 0)
          let resp_bytes = hex_to_bytes(resp_hex)
          let resp = match @codec.decode_message(resp_bytes) {
            Ok(m) => m
            Err(_) => panic()
          }
          assert_eq(resp.answers.length(), 1)
          assert_true(resp.header.aa)
        }
        Err(_) => panic()
      }
    }
    Err(_) => panic()
  }
}
