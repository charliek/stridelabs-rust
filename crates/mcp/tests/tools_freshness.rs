//! The committed `tools/list` contract, the way a service checks it (feature
//! `test-support`): `canonical_tools_json` of a real `#[tool_router]`'s
//! tools, compared with a committed file by
//! `assert_committed_tools_are_fresh`.

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Tool};
use rmcp::{schemars, tool, tool_router, ErrorData};
use stridelabs_mcp::canonical_tools_json;
use stridelabs_mcp::test_support::{
    assert_committed_tools_are_fresh, check_committed_tools, ToolsFreshnessError,
};

const REGEN: &str = "cargo run -- tools > mcp-tools.json";

// Only its schema matters here: the tool never reads it.
#[allow(dead_code)]
#[derive(serde::Deserialize, schemars::JsonSchema)]
struct CreateImage {
    /// What to draw.
    prompt: String,
    /// How many.
    count: Option<u32>,
}

struct Images;

#[tool_router]
impl Images {
    #[tool(description = "Liveness probe; needs no scope.")]
    async fn ping(&self) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![]))
    }

    #[tool(description = "Generate an image.")]
    async fn create_image(
        &self,
        Parameters(_args): Parameters<CreateImage>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![]))
    }
}

fn tools() -> Vec<Tool> {
    let router: ToolRouter<Images> = Images::tool_router();
    router.list_all()
}

fn committed(contents: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("a temp file");
    std::fs::write(file.path(), contents).expect("written");
    file
}

#[test]
fn a_fresh_file_passes_whatever_order_the_router_lists() {
    let file = committed(&canonical_tools_json(&tools()));
    let mut reversed = tools();
    reversed.reverse();

    assert_committed_tools_are_fresh(file.path(), &canonical_tools_json(&reversed), REGEN);
    let json = canonical_tools_json(&tools());
    assert!(
        json.find("\"create_image\"") < json.find("\"ping\""),
        "sorted by name"
    );
    assert!(
        json.contains("\"prompt\""),
        "the input schema is part of the contract"
    );
}

#[test]
fn a_changed_description_is_stale_naming_the_line_and_the_command() {
    let fresh = canonical_tools_json(&tools());
    let file = committed(&fresh.replace("Liveness probe; needs no scope.", "An old description."));

    let error = check_committed_tools(file.path(), &fresh, REGEN).unwrap_err();

    assert!(
        matches!(error, ToolsFreshnessError::Stale { .. }),
        "{error:?}"
    );
    let report = error.to_string();
    assert!(report.contains("first difference at line"), "{report}");
    assert!(report.contains("An old description."), "{report}");
    assert!(
        report.ends_with(&format!("regenerate it with: {REGEN}")),
        "{report}"
    );
}

#[test]
fn a_tool_added_since_the_commit_is_stale() {
    let mut fewer = tools();
    fewer.retain(|tool| tool.name != "ping");
    let file = committed(&canonical_tools_json(&fewer));

    let report = check_committed_tools(file.path(), &canonical_tools_json(&tools()), REGEN)
        .unwrap_err()
        .to_string();

    assert!(report.contains("is stale"), "{report}");
}
