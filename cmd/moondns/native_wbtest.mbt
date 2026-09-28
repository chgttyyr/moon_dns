// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
fn native_test_zone() -> @zone.Zone {
  let zone = @zone.Zone::new("example.com.", 300)
  zone.add_record(
    @types.Record::new(
      "example.com.",
      @types.RType::SOA,
      @types.RClass::IN,
      300,
      @types.RData::SOA(
        "ns.example.com.", "hostmaster.example.com.", 1, 7200, 3600, 1209600, 300,
      ),
    ),
  )
  zone.add_record(
    @types.Record::new(
      "example.com.",
      @types.RType::NS,
      @types.RClass::IN,
      300,
      @types.RData::NS("ns.example.com."),
    ),
  )
  zone.add_record(
    @types.Record::new(
      "www.example.com.",
      @types.RType::A,
      @types.RClass::IN,
      60,
      @types.RData::A(
        (192).to_byte(),
        (0).to_byte(),
        (2).to_byte(),
        (80).to_byte(),
      ),
    ),
  )
  zone.add_record(
    @types.Record::new(
      "www.example.com.",
      @types.RType::AAAA,
      @types.RClass::IN,
      60,
      @types.RData::AAAA(FixedArray::make(16, (0).to_byte())),
    ),
  )
  zone
}

///|
fn assert_native_a_response(payload : Bytes) -> Unit raise {
  match @codec.decode_message(payload) {
    Ok(response) => {
      assert_true(response.header.aa)
      assert_eq(response.answers.length(), 1)
      match response.answers[0].rdata {
        @types.RData::A(a, b, c, d) => {
          assert_eq(a.to_int(), 192)
          assert_eq(b.to_int(), 0)
          assert_eq(c.to_int(), 2)
          assert_eq(d.to_int(), 80)
        }
        _ => fail("Native DNS response did not contain an A record")
      }
    }
    Err(error) => fail(error.message())
  }
}

///|
async test "port zero listeners share the TCP-assigned ephemeral port" {
  let tcp = @socket.TcpServer::TcpServer(
    @socket.Addr::parse("127.0.0.1:0"),
    reuse_addr=true,
  )
  defer tcp.close()
  let udp = bind_udp_listener_for_tcp(tcp)
  defer udp.close()
  assert_true(tcp.addr.port() > 0)
  assert_eq(udp.addr.port(), tcp.addr.port())
}

///|
async test "Native UDP survives malformed datagrams and TCP handles chunked repeated frames" {
  let loopback = @socket.Addr::parse("127.0.0.1:0")
  let tcp = @socket.TcpServer::TcpServer(loopback, reuse_addr=true)
  let port = tcp.addr.port()
  let udp = @socket.UdpServer::UdpServer(
    @socket.Addr::parse("127.0.0.1:" + port.to_string()),
  )
  defer tcp.close()
  defer udp.close()
  let dns_server = @transport.DnsServer::new(native_test_zone())
  let remote = @socket.Addr::resolve("127.0.0.1", port~)
  @async.with_task_group <| root => {
    root.spawn_bg() <| () => { serve_udp_loop(udp, dns_server) }
    root.spawn_bg() <| () => {
      tcp.run_forever(
        (conn, _) => serve_tcp_connection(conn, dns_server),
        max_connections=8,
      )
    }

    let udp_client = @socket.UdpClient::UdpClient(remote)
    defer udp_client.close()
    udp_client.send(Bytes::from_array([(0xff).to_byte(), (0xff).to_byte()]))
    let udp_query = @codec.encode_message(
      @types.Message::new_query(11, "www.example.com.", @types.RType::A),
    )
    udp_client.send(udp_query)
    let udp_buffer = FixedArray::make(65535, (0).to_byte())
    let udp_length = @async.with_timeout(3000, () => udp_client.recv(udp_buffer))
    assert_native_a_response(
      udp_buffer.unsafe_reinterpret_as_bytes()[0:udp_length].to_owned(),
    )

    let tcp_client = @socket.Tcp::connect(remote)
    let tcp_query = @codec.encode_message(
      @types.Message::new_query(12, "www.example.com.", @types.RType::A),
    )
    let tcp_frame = @transport.encode_tcp_frame(tcp_query)
    @io.Writer::write(tcp_client, tcp_frame[0:1].to_owned())
    @async.sleep(10)
    @io.Writer::write(tcp_client, tcp_frame[1:2].to_owned())
    @async.sleep(10)
    @io.Writer::write(tcp_client, tcp_frame[2:6].to_owned())
    @async.sleep(10)
    @io.Writer::write(tcp_client, tcp_frame[6:].to_owned())
    let response_prefix = @io.Reader::read_exactly(tcp_client, 2)
    let response_length = response_prefix[0].to_int() * 256 +
      response_prefix[1].to_int()
    assert_native_a_response(
      @io.Reader::read_exactly(tcp_client, response_length),
    )

    let second_frame = @transport.encode_tcp_frame(
      @codec.encode_message(
        @types.Message::new_query(13, "www.example.com.", @types.RType::A),
      ),
    )
    @io.Writer::write(tcp_client, second_frame)
    let second_prefix = @io.Reader::read_exactly(tcp_client, 2)
    let second_length = second_prefix[0].to_int() * 256 +
      second_prefix[1].to_int()
    assert_native_a_response(
      @io.Reader::read_exactly(tcp_client, second_length),
    )
    tcp_client.close()

    let rejected_client = @socket.Tcp::connect(remote)
    @io.Writer::write(
      rejected_client,
      Bytes::from_array([(0).to_byte(), (0).to_byte()]),
    )
    let close_observed = @async.with_timeout_opt(1500, () => {
      try {
        ignore(@io.Reader::read_exactly(rejected_client, 1))
        false
      } catch {
        @io.ReaderClosed => true
        error => raise error
      }
    })
    assert_eq(close_observed, Some(true))
    rejected_client.close()

    let after_bad_frame = @socket.UdpClient::UdpClient(remote)
    defer after_bad_frame.close()
    after_bad_frame.send(udp_query)
    let final_buffer = FixedArray::make(65535, (0).to_byte())
    let final_length = @async.with_timeout(3000, () => {
      after_bad_frame.recv(final_buffer)
    })
    assert_native_a_response(
      final_buffer.unsafe_reinterpret_as_bytes()[0:final_length].to_owned(),
    )
    root.return_immediately(())
  }
}
