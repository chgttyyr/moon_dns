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
