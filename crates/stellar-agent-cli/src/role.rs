//! Selects the process role from the invocation before any initialization.

use std::ffi::OsString;

use stellar_agent_mcp::entry::{INVOKED_NAME_ROUTE, SUBCOMMAND_ROUTE};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Server {
        skip: usize,
        display_name: &'static str,
    },
    Tool,
}

pub(crate) fn select(args: &[OsString], windows: bool) -> Role {
    let server_name = args.first().is_some_and(|name| {
        // Encoded bytes preserve exact matching even with a non-Unicode parent.
        let name = name.as_encoded_bytes();
        let component = name
            .rsplit(|byte| *byte == b'/' || (windows && *byte == b'\\'))
            .next()
            .unwrap_or_default();
        if windows {
            component.eq_ignore_ascii_case(INVOKED_NAME_ROUTE.as_bytes())
                || component.eq_ignore_ascii_case(format!("{INVOKED_NAME_ROUTE}.exe").as_bytes())
        } else {
            component == INVOKED_NAME_ROUTE.as_bytes()
        }
    });
    if server_name {
        Role::Server {
            skip: 1,
            display_name: INVOKED_NAME_ROUTE,
        }
    } else if args.get(1).is_some_and(|arg| arg == "mcp")
        && args.get(2).is_some_and(|arg| arg == "serve")
    {
        Role::Server {
            skip: 3,
            display_name: SUBCOMMAND_ROUTE,
        }
    } else {
        Role::Tool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(args: &[&str], windows: bool) -> Role {
        select(
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            windows,
        )
    }

    fn server() -> Role {
        Role::Server {
            skip: 1,
            display_name: INVOKED_NAME_ROUTE,
        }
    }

    #[test]
    fn directory_name_does_not_select() {
        for windows in [false, true] {
            assert_eq!(role(&["/x/stellar-agent-mcp/tool"], windows), Role::Tool);
            assert_eq!(role(&["/x/stellar-agent-mcp"], windows), server());
        }
    }

    #[test]
    fn exe_suffix_rule() {
        for path in [
            "stellar-agent-mcp.exe",
            "/x/stellar-agent-mcp.exe",
            r"C:\x\stellar-agent-mcp.exe",
        ] {
            assert_eq!(role(&[path], false), Role::Tool);
            assert_eq!(role(&[path], true), server());
        }
        assert_eq!(role(&[r"C:\x\stellar-agent-mcp"], false), Role::Tool);
        assert_eq!(role(&[r"C:\x\stellar-agent-mcp"], true), server());
    }

    #[test]
    fn windows_folds_ascii_case() {
        for path in [
            "Stellar-Agent-MCP.EXE",
            r"C:\x\Stellar-Agent-MCP",
            "/x/STELLAR-AGENT-MCP.exe",
        ] {
            assert_eq!(role(&[path], true), server());
        }
    }

    #[test]
    fn unix_compares_exactly() {
        assert_eq!(role(&["Stellar-Agent-MCP"], false), Role::Tool);
        assert_eq!(role(&["stellar-agent-mcp-old"], false), Role::Tool);
        assert_eq!(role(&["stellar-agent-mcp"], false), server());
    }

    #[test]
    fn subcommand_position_and_name_precedence() {
        for windows in [false, true] {
            assert_eq!(role(&[], windows), Role::Tool);
            assert_eq!(role(&["tool", "mcp"], windows), Role::Tool);
            assert_eq!(role(&["tool", "pay", "mcp", "serve"], windows), Role::Tool);
            assert_eq!(role(&["tool", "MCP", "serve"], windows), Role::Tool);
            assert_eq!(
                role(&["tool", "mcp", "serve"], windows),
                Role::Server {
                    skip: 3,
                    display_name: SUBCOMMAND_ROUTE,
                }
            );
            assert_eq!(
                role(&["stellar-agent-mcp", "mcp", "serve"], windows),
                server()
            );
        }
    }
}
