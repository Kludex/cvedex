//! cvedex: a CVE Services client library. `Client` speaks the CVE Services API to MITRE or to a
//! `cvedexd` policy server, `config` loads credentials, `record` holds the CVE JSON shapes.

pub const client = @import("client.zig");
pub const config = @import("config.zig");
pub const record = @import("record.zig");

pub const Client = client.Client;
pub const Credentials = client.Credentials;
pub const Response = client.Response;
pub const Escaped = client.Escaped;

/// Scripted CVE Services stand-in, for tests of code built on this library.
pub const Upstream = @import("Upstream.zig");

test {
    _ = client;
    _ = config;
    _ = record;
    _ = Upstream;
}
