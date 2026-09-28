// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
fn print_section(label : String, records : Array[@types.Record]) -> Unit {
  println(label + ":")
  if records.length() == 0 {
    println("  (empty)")
  }
  for record in records {
    println(
      "  " +
      record.name +
      " " +
      record.ttl.to_string() +
      " " +
      record.rclass.to_string() +
      " " +
      record.rtype.to_string() +
      " " +
      record.rdata.to_presentation(),
    )
  }
}

///|
/// Send one UDP DNS request and print all decoded response sections.
async fn run_query(
  host : String,
  port : UInt16,
  name : String,
  qtype : @types.RType,
) -> Unit {
  let remote = @socket.Addr::resolve(host, port=port.to_int()) catch {
    error =>
      raise Failure::Failure(
        "cannot resolve DNS server address: " + @debug.to_string(error),
      )
  }
  let client = @socket.UdpClient::UdpClient(remote) catch {
    error =>
      raise Failure::Failure(
        "cannot create DNS UDP socket: " + @debug.to_string(error),
      )
  }
  defer client.close()

  let id = @async.now().to_uint16()
  let request = @codec.encode_message(
    @types.Message::new_query(id, name, qtype),
  )
  let response = @async.with_timeout_opt(5000, () => {
    client.send(request)
    let buffer = FixedArray::make(65535, (0).to_byte())
    let received = client.recv(buffer)
    buffer.unsafe_reinterpret_as_bytes()[0:received].to_owned()
  }) catch {
    error =>
      raise Failure::Failure("DNS query I/O failed: " + @debug.to_string(error))
  }
  let response_bytes = match response {
    Some(bytes) => bytes
    None => raise Failure::Failure("DNS query timed out after 5 seconds")
  }
  let response = match @codec.decode_message(response_bytes) {
    Ok(message) => message
    Err(error) =>
      raise Failure::Failure("Malformed DNS response: " + error.message())
  }

  println("ID: " + response.header.id.to_string())
  println("RCODE: " + response.header.rcode.to_wire().to_string())
  println("AA: " + response.header.aa.to_string())
  print_section("Answer", response.answers)
  print_section("Authority", response.authorities)
  print_section("Additional", response.additionals)
}
