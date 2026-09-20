// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///| System test harness helper verifying end-to-end DNS stack components
pub fn run_system_health_check() -> Bool {
  let zone = @zone.Zone::new("system.test.", 300)
  let a_rec = @types.Record::new(
    "system.test.",
    @types.RType::A,
    @types.RClass::IN,
    300,
    @types.RData::A((127).to_byte(), (0).to_byte(), (0).to_byte(), (1).to_byte())
  )
  zone.add_record(a_rec)

  let server = @transport.DnsServer::new(zone)
  let q = @types.Message::new_query(0x9999, "system.test.", @types.RType::A)
  let cmap = @compression.CompressionMap::new()
  let writer = @bytes_io.ByteWriter::new()
  let _ = @domain.encode_domain_labels(writer, "system.test.")
  let _ = @records.encode_rdata_a(writer, (127).to_byte(), (0).to_byte(), (0).to_byte(), (1).to_byte())

  let raw_q = @codec.encode_message(q)
  match server.process_udp(raw_q) {
    Ok(raw_resp) => {
      let resp = match @codec.decode_message(raw_resp) {
        Ok(m) => m
        Err(_) => return false
      }
      let opt = @records.OptRecord::new(1232, false)
      resp.add_additional(opt.to_record())
      let _ = @resolver.truncate_response(resp, 1232)
      cmap.insert("system.test.", 0)
      true
    }
    Err(_) => false
  }
}
