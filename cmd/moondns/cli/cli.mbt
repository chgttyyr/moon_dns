// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
/// Native command line operations supported by MoonDNS.
pub(all) enum CLICommand {
  Serve(String, String, String, UInt16, Int)
  Query(String, UInt16, String, @types.RType)
  Check(String, String)
  Help
} derive(Debug, Eq)

///|
/// Parse a bounded unsigned decimal command-line value.
fn parse_decimal(text : String, maximum : Int) -> Int? {
  if text.length() == 0 {
    return None
  }
  let mut value = 0
  for i = 0; i < text.length(); i = i + 1 {
    let ch = text[i].to_int()
    if ch < 48 || ch > 57 {
      return None
    }
    value = value * 10 + ch - 48
    if value > maximum {
      return None
    }
  }
  Some(value)
}

///|
fn is_command(word : String) -> Bool {
  word == "serve" || word == "query" || word == "check" || word == "help"
}

///|
/// Parse CLI arguments; accepts either command-first args or argv with an executable prefix.
pub fn parse_cli(args : Array[String]) -> Result[CLICommand, String] {
  if args.length() == 0 {
    return Ok(Help)
  }
  let mut command_index = 0
  if !is_command(args[0]) && args[0] != "--help" && args[0] != "-h" {
    if args.length() > 1 {
      command_index = 1
    } else {
      return Err("unknown command: " + args[0])
    }
  }
  if command_index >= args.length() ||
    args[command_index] == "--help" ||
    args[command_index] == "-h" ||
    args[command_index] == "help" {
    return Ok(Help)
  }

  let command = args[command_index]
  if !is_command(command) {
    return Err("unknown command: " + command)
  }

  let mut zone_path = ""
  let mut origin = ""
  let mut listen_host = "127.0.0.1"
  let mut server_host = "127.0.0.1"
  let mut port : UInt16 = 5353
  let mut max_connections = 64
  let mut used_zone = false
  let mut used_origin = false
  let mut used_listen = false
  let mut used_server = false
  let mut used_port = false
  let mut used_max_connections = false
  let positional : Array[String] = []
  let mut index = command_index + 1

  while index < args.length() {
    let token = args[index]
    if token == "--help" || token == "-h" {
      return Ok(Help)
    }
    if token == "-z" ||
      token == "--zone" ||
      token == "-o" ||
      token == "--origin" ||
      token == "--listen" ||
      token == "-s" ||
      token == "--server" ||
      token == "-p" ||
      token == "--port" ||
      token == "--max-connections" {
      if index + 1 >= args.length() {
        return Err("missing value for " + token)
      }
      let value = args[index + 1]
      match token {
        "-z" | "--zone" => {
          zone_path = value
          used_zone = true
        }
        "-o" | "--origin" => {
          origin = value
          used_origin = true
        }
        "--listen" => {
          listen_host = value
          used_listen = true
        }
        "-s" | "--server" => {
          server_host = value
          used_server = true
        }
        "-p" | "--port" => {
          used_port = true
          port = match parse_decimal(value, 65535) {
            Some(number) => number.to_uint16()
            None =>
              return Err("port must be a decimal number in the range 0..65535")
          }
        }
        "--max-connections" => {
          used_max_connections = true
          max_connections = match parse_decimal(value, 65535) {
            Some(number) if number > 0 => number
            _ => return Err("max-connections must be in the range 1..65535")
          }
        }
        _ => ()
      }
      index = index + 2
    } else if token.has_prefix("-") {
      return Err("unknown option for " + command + ": " + token)
    } else {
      positional.push(token)
      index = index + 1
    }
  }

  match command {
    "check" => {
      if zone_path.length() == 0 || origin.length() == 0 {
        return Err("check requires --zone and --origin")
      }
      if positional.length() != 0 ||
        used_listen ||
        used_server ||
        used_port ||
        used_max_connections {
        return Err("option not supported by check")
      }
      Ok(Check(zone_path, origin))
    }
    "serve" => {
      if zone_path.length() == 0 || origin.length() == 0 {
        return Err("serve requires --zone and --origin")
      }
      if positional.length() != 0 || used_server {
        return Err("option not supported by serve")
      }
      Ok(Serve(zone_path, origin, listen_host, port, max_connections))
    }
    "query" => {
      if used_zone || used_origin || used_listen || used_max_connections {
        return Err("option not supported by query")
      }
      if positional.length() != 2 {
        return Err("query requires exactly a domain name and RR type")
      }
      let qtype = match @types.RType::from_string(positional[1].to_upper()) {
        Some(@types.RType::OPT)
        | Some(@types.RType::AXFR)
        | Some(@types.RType::Unknown(_))
        | None => return Err("unsupported query type: " + positional[1])
        Some(value) => value
      }
      Ok(Query(server_host, port, positional[0], qtype))
    }
    "help" => Ok(Help)
    _ => Err("unknown command: " + command)
  }
}

///|
/// Render the Native CLI usage summary.
pub fn usage() -> String {
  "MoonDNS Native CLI\n" +
  "  moondns check -z <zone-file> -o <origin>\n" +
  "  moondns serve -z <zone-file> -o <origin> [--listen <host>] [-p <port>] [--max-connections <n>]\n" +
  "  moondns query [-s <server>] [-p <port>] <name> <type>\n" +
  "Defaults: listen/server 127.0.0.1, port 5353, max connections 64."
}
