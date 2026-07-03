//! Compile-fail coverage for `#[mcp_tool_router]` diagnostics.

#[test]
fn compile_fail_suite() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
