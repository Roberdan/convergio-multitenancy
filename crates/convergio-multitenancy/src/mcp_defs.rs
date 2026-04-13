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
            description: "Set resource limits for a tenancy org.".into(),
            method: "POST".into(),
            path: "/api/tenancy/resources".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "org_id": {"type": "string"},
                    "max_cpu_seconds_per_hour": {"type": "integer"},
                    "max_memory_mb": {"type": "integer"},
                    "max_storage_mb": {"type": "integer"},
                    "max_concurrent_agents": {"type": "integer"},
                    "max_api_calls_per_minute": {"type": "integer"}
                },
                "required": ["org_id"]
            }),
            min_ring: "trusted".into(),
            path_params: vec![],
        },
    ]
}
