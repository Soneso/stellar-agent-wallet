//! Compatibility executable for the MCP stdio server.

use stellar_agent_mcp::entry::INVOKED_NAME_ROUTE;

fn main() -> ! {
    stellar_agent_mcp::entry::run_server_process(INVOKED_NAME_ROUTE, std::env::args().skip(1))
}
