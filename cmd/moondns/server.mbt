// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
/// Handle a TCP connection as a sequence of RFC 1035 length-prefixed DNS messages.
async fn serve_tcp_connection(
  conn : @socket.Tcp,
  dns_server : @transport.DnsServer,
) -> Unit {
  while true {
    let prefix = @io.Reader::read_exactly(conn, 2)
    let length = prefix[0].to_int() * 256 + prefix[1].to_int()
    if length == 0 {
      return
    }
    let query = @io.Reader::read_exactly(conn, length)
    match dns_server.process_tcp(@transport.encode_tcp_frame(query)) {
      Ok(response_frame) => @io.Writer::write(conn, response_frame)
      Err(_) => return
    }
  }
}

///|
/// Receive UDP requests without allowing one malformed datagram to stop the listener.
async fn serve_udp_loop(
  udp : @socket.UdpServer,
  dns_server : @transport.DnsServer,
) -> Unit {
  let mut dropped_datagrams = 0
  while true {
    let buffer = FixedArray::make(65535, (0).to_byte())
    let (received, remote) = udp.recvfrom(buffer)
    let packet = buffer.unsafe_reinterpret_as_bytes()[0:received].to_owned()
    match dns_server.process_udp(packet) {
      Ok(response) => udp.sendto(response, remote)
      Err(_) => {
        dropped_datagrams = dropped_datagrams + 1
        if dropped_datagrams == 1 || dropped_datagrams % 1000 == 0 {
          println(
            "Dropped malformed DNS datagrams: " + dropped_datagrams.to_string(),
          )
        }
      }
    }
  }
}

///|
/// Bind UDP on the TCP server's actual address, including an OS-assigned port.
async fn bind_udp_listener_for_tcp(
  tcp : @socket.TcpServer,
) -> @socket.UdpServer {
  @socket.UdpServer::UdpServer(tcp.addr)
}

///|
/// Start UDP and TCP listeners on the same address and port.
async fn serve_authoritative(
  zone : @zone.Zone,
  host : String,
  port : UInt16,
  max_connections : Int,
) -> Unit {
  let address_text = if host.contains(":") && !host.has_prefix("[") {
    "[" + host + "]:" + port.to_string()
  } else {
    host + ":" + port.to_string()
  }
  let requested_address = @socket.Addr::parse(address_text)
  let tcp = @socket.TcpServer::TcpServer(requested_address, reuse_addr=true)
  defer tcp.close()
  let udp = bind_udp_listener_for_tcp(tcp)
  defer udp.close()

  println(
    "Serving " + zone.origin + " on " + tcp.addr.to_string() + " (UDP/TCP)",
  )
  println("Maximum concurrent TCP connections: " + max_connections.to_string())
  let dns_server = @transport.DnsServer::new(zone)
  @async.with_task_group <| root => {
    root.spawn_bg() <| () => { serve_udp_loop(udp, dns_server) }
    tcp.run_forever(
      (conn, _) => serve_tcp_connection(conn, dns_server),
      max_connections~,
    )
  }
}
