//! The canonical `tools/list` JSON: an MCP service's committed contract.
//!
//! A service with no REST API has no OpenAPI document; its contract is the
//! tool list — names, descriptions, input and output schemas, annotations.
//! Committing it (`mcp-tools.json`) makes every change to that contract a
//! reviewable diff, and `test_support::assert_committed_tools_are_fresh`
//! (feature `test-support`) fails the build when the file and the code
//! disagree. Not gated: the service's own binary prints it
//! (`svc tools > mcp-tools.json`).

use std::collections::BTreeMap;

use rmcp::model::Tool;
use serde_json::Value;

/// `{"tools": [...]}` with the tools sorted by name and every object's keys
/// sorted at every depth, pretty-printed, LF line endings and one trailing
/// newline.
///
/// Byte-identical run to run, whatever order a `ToolRouter` lists its tools
/// in and whatever `serde_json` features the build graph unified
/// (`preserve_order` makes maps insertion-ordered), so a committed copy is
/// only ever stale for a real reason.
pub fn canonical_tools_json(tools: &[Tool]) -> String {
    let mut tools = tools.to_vec();
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    let value = serde_json::json!({ "tools": tools });
    let pretty =
        serde_json::to_string_pretty(&canonicalize(value)).expect("a JSON value always serializes");
    format!("{pretty}\n")
}

/// Rebuild every object with its keys in sorted order.
fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn tool(name: &str) -> Tool {
        let Value::Object(schema) =
            serde_json::json!({"type": "object", "properties": {"z": {}, "a": {}}})
        else {
            unreachable!("an object literal")
        };
        Tool::new(
            name.to_owned(),
            format!("the {name} tool"),
            Arc::new(schema),
        )
    }

    #[test]
    fn tools_and_keys_are_sorted_at_every_depth() {
        let json = canonical_tools_json(&[tool("zeta"), tool("alpha")]);

        assert!(json.starts_with("{\n  \"tools\": [\n"), "{json}");
        assert!(json.ends_with("}\n") && !json.ends_with("\n\n"), "{json}");
        assert!(!json.contains('\r'));
        let at = |needle: &str| json.find(needle).expect(needle);
        assert!(at("\"alpha\"") < at("\"zeta\""));
        assert!(at("\"a\": {}") < at("\"z\": {}"));
        assert!(at("\"description\"") < at("\"inputSchema\""));
        assert!(at("\"inputSchema\"") < at("\"name\""));
    }

    #[test]
    fn the_output_ignores_the_input_order() {
        assert_eq!(
            canonical_tools_json(&[tool("b"), tool("a")]),
            canonical_tools_json(&[tool("a"), tool("b")])
        );
    }

    #[test]
    fn no_tools_is_an_empty_list() {
        assert_eq!(canonical_tools_json(&[]), "{\n  \"tools\": []\n}\n");
    }
}
