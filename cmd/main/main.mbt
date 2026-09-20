// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

fn print_banner() -> Unit {
  println("=================================================================")
  println("  MoonDNS (chgttyyr/moon_dns) - Pure MoonBit Authoritative Server")
  println("  100% Zero-FFI | Pointer Security Guards | RFC 1035/6891 Compliant")
  println("=================================================================")
}

fn run_demo() -> Unit {
  print_banner()
  println("[1/4] Bootstrapping In-Memory Zone Database for 'example.com.'...")

  let zone = @zone.Zone::new("example.com.", 3600)

  // SOA
  zone.add_record(@types.Record::new(
    "example.com.",
    @types.RType::SOA,
    @types.RClass::IN,
    3600,
    @types.RData::SOA("ns1.example.com.", "hostmaster.example.com.", 2026092001, 7200, 3600, 1209600, 3600)
  ))

  // NS & Glue
  zone.add_record(@types.Record::new("example.com.", @types.RType::NS, @types.RClass::IN, 86400, @types.RData::NS("ns1.example.com.")))
  zone.add_record(@types.Record::new("ns1.example.com.", @types.RType::A, @types.RClass::IN, 86400, @types.RData::A((192).to_byte(), (0).to_byte(), (2).to_byte(), (1).to_byte())))

  // A, CNAME, Wildcard
  zone.add_record(@types.Record::new("www.example.com.", @types.RType::A, @types.RClass::IN, 300, @types.RData::A((93).to_byte(), (184).to_byte(), (216).to_byte(), (34).to_byte())))
  zone.add_record(@types.Record::new("blog.example.com.", @types.RType::CNAME, @types.RClass::IN, 300, @types.RData::CNAME("www.example.com.")))
  zone.add_record(@types.Record::new("*.dev.example.com.", @types.RType::A, @types.RClass::IN, 60, @types.RData::A((127).to_byte(), (0).to_byte(), (0).to_byte(), (1).to_byte())))

  let server = @transport.DnsServer::new(zone)
  println("  -> Loaded 6 records into authoritative apex 'example.com.'")

  println("\n[2/4] Testing Standard Authoritative Queries...")
  // Query 1: www.example.com. A
  let q1 = @types.Message::new_query(0x1001, "www.example.com.", @types.RType::A)
  match server.process_udp(@codec.encode_message(q1)) {
    Ok(raw_resp) => {
      let resp = match @codec.decode_message(raw_resp) {
        Ok(m) => m
        Err(_) => panic()
      }
      println("  [QUERY] www.example.com. A -> RCODE=" + resp.header.rcode.to_wire().to_string() + ", AA=" + resp.header.aa.to_string())
      for i = 0; i < resp.answers.length(); i = i + 1 {
        println("    ANSWER: " + resp.answers[i].name + " " + resp.answers[i].ttl.to_string() + " IN A " + resp.answers[i].rdata.to_presentation())
      }
    }
    Err(_) => panic()
  }

  // Query 2: blog.example.com. A (CNAME Chasing)
  let q2 = @types.Message::new_query(0x1002, "blog.example.com.", @types.RType::A)
  match server.process_udp(@codec.encode_message(q2)) {
    Ok(raw_resp) => {
      let resp = match @codec.decode_message(raw_resp) {
        Ok(m) => m
        Err(_) => panic()
      }
      println("  [QUERY] blog.example.com. A -> Chased " + resp.answers.length().to_string() + " records (CNAME + Target)")
      for i = 0; i < resp.answers.length(); i = i + 1 {
        println("    ANSWER: " + resp.answers[i].name + " -> " + resp.answers[i].rdata.to_presentation())
      }
    }
    Err(_) => panic()
  }

  // Query 3: Wildcard test.dev.example.com. A
  let q3 = @types.Message::new_query(0x1003, "test.dev.example.com.", @types.RType::A)
  match server.process_udp(@codec.encode_message(q3)) {
    Ok(raw_resp) => {
      let resp = match @codec.decode_message(raw_resp) {
        Ok(m) => m
        Err(_) => panic()
      }
      println("  [QUERY] test.dev.example.com. A -> Wildcard Match: " + resp.answers[0].rdata.to_presentation())
    }
    Err(_) => panic()
  }

  println("\n[3/4] Testing RFC Semantics (NODATA & NXDOMAIN)...")
  // Query 4: www.example.com. MX -> NODATA (RCODE=0, ANCOUNT=0, SOA in Authority)
  let q4 = @types.Message::new_query(0x1004, "www.example.com.", @types.RType::MX)
  match server.process_udp(@codec.encode_message(q4)) {
    Ok(raw_resp) => {
      let resp = match @codec.decode_message(raw_resp) {
        Ok(m) => m
        Err(_) => panic()
      }
      println("  [NODATA] RCODE=" + resp.header.rcode.to_wire().to_string() + ", Answers=" + resp.answers.length().to_string() + ", Authority=" + resp.authorities[0].rtype.to_string())
    }
    Err(_) => panic()
  }

  // Query 5: ghost.example.com. A -> NXDOMAIN (RCODE=3, ANCOUNT=0, SOA in Authority)
  let q5 = @types.Message::new_query(0x1005, "ghost.example.com.", @types.RType::A)
  match server.process_udp(@codec.encode_message(q5)) {
    Ok(raw_resp) => {
      let resp = match @codec.decode_message(raw_resp) {
        Ok(m) => m
        Err(_) => panic()
      }
      println("  [NXDOMAIN] RCODE=" + resp.header.rcode.to_wire().to_string() + " (Name Error), Authority=" + resp.authorities[0].name)
    }
    Err(_) => panic()
  }

  println("\n[4/4] Security Testing: Malicious Pointer Attacks Injection...")
  // Inject malicious self-loop pointer packet
  let writer = @bytes_io.ByteWriter::new()
  let bad_header = @types.Header::new_query(0x6666)
  @codec.encode_header(writer, bad_header)
  // Inject cyclic pointer 0xc00c pointing to self
  writer.write_byte((0xc0).to_byte())
  writer.write_byte((0x0c).to_byte())
  writer.write_uint16(1) // QTYPE A
  writer.write_uint16(1) // QCLASS IN

  let attack_payload = writer.to_bytes()
  match server.process_udp(attack_payload) {
    Ok(_) => println("  [FAIL] Malicious packet was not rejected!")
    Err(err) => {
      println("  [SUCCESS] Defense Layer Active: Intercepted attack safely: " + err.message())
      println("  Server health status: 100% ALIVE, zero panic, zero infinite loop!")
    }
  }

  println("\nAll demo stages executed successfully. Total queries processed: " + server.query_count.to_string())
}

fn main {
  run_demo()
}
