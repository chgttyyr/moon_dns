// MoonDNS - Pure MoonBit Authoritative DNS Server
// Copyright 2026 chgttyyr
// Licensed under the Apache-2.0 License.

///|
/// Read a Zone file and parse it with the requested apex.
async fn load_zone(path : String, origin : String) -> @zone.Zone {
  let source = @fs.read_file(path).text() catch {
    error =>
      raise Failure::Failure(
        "cannot read Zone file " + path + ": " + @debug.to_string(error),
      )
  }
  match @zone.parse_zone_text(origin, source) {
    Ok(zone) => zone
    Err(error) =>
      raise Failure::Failure("Zone parse failed: " + error.message())
  }
}

///|
/// Check Zone structure and print a concise acceptance summary.
async fn check_zone(path : String, origin : String) -> Unit {
  let zone = load_zone(path, origin)
  let errors = zone.validate()
  if errors.length() != 0 {
    for message in errors {
      println("ERROR: " + message)
    }
    raise Failure::Failure("Zone validation failed")
  }
  println("Zone: " + zone.origin)
  println("Records: " + zone.record_count().to_string())
  println("Apex SOA: valid")
  println("Apex NS: valid")
}

///|
/// Validate and load a Zone before binding the Native DNS listeners.
async fn start_zone_server(
  path : String,
  origin : String,
  host : String,
  port : UInt16,
  max_connections : Int32,
) -> Unit {
  let zone = load_zone(path, origin)
  let errors = zone.validate()
  if errors.length() != 0 {
    for message in errors {
      println("ERROR: " + message)
    }
    raise Failure::Failure("Zone validation failed")
  }
  serve_authoritative(zone, host, port, max_connections)
}

///|
/// Execute the Native CLI after parsing argv.
async fn execute_cli() -> Unit {
  match @cli.parse_cli(@env.args()) {
    Ok(@cli.CLICommand::Help) => println(@cli.usage())
    Ok(@cli.CLICommand::Check(path, origin)) => check_zone(path, origin)
    Ok(@cli.CLICommand::Serve(path, origin, host, port, max_connections)) =>
      start_zone_server(path, origin, host, port, max_connections)
    Ok(@cli.CLICommand::Query(host, port, name, qtype)) =>
      run_query(host, port, name, qtype)
    Err(message) => {
      println("ERROR: " + message)
      println(@cli.usage())
      raise Failure::Failure("invalid command line")
    }
  }
}
