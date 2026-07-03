use stellar_agent_mcp_macros::mcp_tool_router;

struct Dummy;

#[mcp_tool_router]
impl Dummy {
    #[mcp_tool_item(
        name = "stellar_pay",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[mcp_tool_item(
        name = "stellar_pay",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = false
    )]
    fn stellar_pay(&self) {}
}

fn main() {}
