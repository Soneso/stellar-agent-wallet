use stellar_agent_mcp_macros::mcp_tool_router;

struct Dummy;

#[mcp_tool_router]
impl Dummy {
    #[tool(name = "stellar_pay")]
    fn stellar_pay(&self) {}
}

fn main() {}
