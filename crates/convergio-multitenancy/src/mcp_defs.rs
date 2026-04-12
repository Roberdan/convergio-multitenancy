//! MCP tool definitions for the multitenancy extension.

use convergio_types::extension::McpToolDef;
use serde_json::json;

pub fn tenancy_tools() -> Vec<McpToolDef> {
    vec![
        McpToolDef {
            name: "cvg_list_tenancy_peers".into(),
            description: "List tenancy peers.".into(),
            method: "GET".into(),
            path: "/api/tenancy/peers".into(),
            input_schema: json!({"type": "object", "properties": {}}),
            min_ring: "community".into(),
            path_params: vec![],
        },
        McpToolDef {
            name: "cvg_tenancy_audit".into(),
            description: "Get tenancy audit log.".into(),
            method: "GET".into(),
            path: "/api/tenancy/audit".into(),
            input_schema: json!({"type": "object", "properties": {}}),
            min_ring: "community".into(),
            path_params: vec![],
        },
        McpToolDef {
            name: "cvg_list_tenancy_resources".into(),
            description: "List tenancy resources.".into(),
            method: "GET".into(),
            path: "/api/tenancy/resources".into(),
            input_schema: json!({"type": "object", "properties": {}}),
            min_ring: "community".into(),
            path_params: vec![],
        },
        McpToolDef {
            name: "cvg_create_tenancy_resource".into(),
            description: "Create a tenancy resource.".into(),
            method: "POST".into(),
            path: "/api/tenancy/resources".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string"}
                },
                "required": ["name", "type"]
            }),
            min_ring: "trusted".into(),
            path_params: vec![],
        },
    ]
}
