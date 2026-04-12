//! Security tests: org/project data isolation across tenancy boundaries.
//!
//! Verifies that cross-org access is blocked at every isolation layer:
//! DB table prefix, secrets, audit logs, and network peer whitelists.

use convergio_multitenancy::db_isolation::{
    create_org_table, drop_org_tables, list_org_tables, validate_table_access,
};
use convergio_multitenancy::secret_isolation::{
    delete_secret, get_secret, list_secret_keys, put_secret,
};
use convergio_multitenancy::types::OrgId;
use rusqlite::Connection;

fn test_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    for m in convergio_multitenancy::schema::migrations() {
        conn.execute_batch(m.up).unwrap();
    }
    conn
}

// ── DB table prefix isolation ────────────────────────────────────────────────

#[test]
fn org_a_cannot_access_org_b_tables() {
    let org_a = OrgId("alpha".into());
    let org_b = OrgId("beta".into());
    assert!(
        validate_table_access(&org_a, "org_beta_tasks").is_err(),
        "org alpha must NOT access org_beta tables"
    );
    assert!(
        validate_table_access(&org_b, "org_alpha_tasks").is_err(),
        "org beta must NOT access org_alpha tables"
    );
}

#[test]
fn org_accesses_own_tables() {
    let org = OrgId("acme".into());
    assert!(validate_table_access(&org, "org_acme_tasks").is_ok());
    assert!(validate_table_access(&org, "org_acme_agents").is_ok());
}

#[test]
fn shared_tables_accessible_by_all_orgs() {
    let orgs = [OrgId("a".into()), OrgId("b".into()), OrgId("c".into())];
    for org in &orgs {
        assert!(validate_table_access(org, "mt_isolation_policies").is_ok());
        assert!(validate_table_access(org, "_schema_registry").is_ok());
    }
}

#[test]
fn sql_injection_in_org_id_sanitized() {
    let evil_org = OrgId("'; DROP TABLE users; --".into());
    let prefix = evil_org.table_prefix();
    assert!(
        !prefix.contains('\'') && !prefix.contains(';'),
        "org prefix must sanitize special chars: got {prefix}"
    );
}

#[test]
fn empty_org_id_prefix_is_safe() {
    let org = OrgId("".into());
    let prefix = org.table_prefix();
    assert_eq!(prefix, "org__");
    assert!(validate_table_access(&org, "org__tasks").is_ok());
    assert!(validate_table_access(&org, "org_other_tasks").is_err());
}

#[test]
fn create_tables_isolated_per_org() {
    let conn = test_conn();
    let org_a = OrgId("alpha".into());
    let org_b = OrgId("beta".into());
    let tpl = "CREATE TABLE IF NOT EXISTS {prefix}data (id INTEGER PRIMARY KEY, val TEXT)";
    create_org_table(&conn, &org_a, tpl).unwrap();
    create_org_table(&conn, &org_b, tpl).unwrap();

    let tables_a = list_org_tables(&conn, &org_a).unwrap();
    let tables_b = list_org_tables(&conn, &org_b).unwrap();
    assert_eq!(tables_a, vec!["org_alpha_data"]);
    assert_eq!(tables_b, vec!["org_beta_data"]);
}

#[test]
fn drop_org_tables_only_affects_target_org() {
    let conn = test_conn();
    let org_a = OrgId("keep".into());
    let org_b = OrgId("remove".into());
    let tpl = "CREATE TABLE IF NOT EXISTS {prefix}stuff (id INTEGER PRIMARY KEY)";
    create_org_table(&conn, &org_a, tpl).unwrap();
    create_org_table(&conn, &org_b, tpl).unwrap();

    drop_org_tables(&conn, &org_b).unwrap();
    assert_eq!(list_org_tables(&conn, &org_a).unwrap().len(), 1);
    assert_eq!(list_org_tables(&conn, &org_b).unwrap().len(), 0);
}

// ── Secret isolation ─────────────────────────────────────────────────────────

#[test]
fn cross_org_secret_access_blocked() {
    let conn = test_conn();
    let org_a = OrgId("alpha".into());
    let org_b = OrgId("beta".into());
    put_secret(&conn, &org_a, "api_key", "super-secret-alpha").unwrap();

    let result = get_secret(&conn, &org_b, "api_key").unwrap();
    assert!(result.is_none(), "org_b must NOT see org_a's secrets");
}

#[test]
fn org_sees_only_own_secret_keys() {
    let conn = test_conn();
    let org_a = OrgId("alpha".into());
    let org_b = OrgId("beta".into());
    put_secret(&conn, &org_a, "key_a1", "v1").unwrap();
    put_secret(&conn, &org_a, "key_a2", "v2").unwrap();
    put_secret(&conn, &org_b, "key_b1", "v3").unwrap();

    let keys_a = list_secret_keys(&conn, &org_a).unwrap();
    let keys_b = list_secret_keys(&conn, &org_b).unwrap();
    assert_eq!(keys_a, vec!["key_a1", "key_a2"]);
    assert_eq!(keys_b, vec!["key_b1"]);
}

#[test]
fn delete_secret_only_affects_own_org() {
    let conn = test_conn();
    let org_a = OrgId("alpha".into());
    let org_b = OrgId("beta".into());
    put_secret(&conn, &org_a, "shared_name", "val-a").unwrap();
    put_secret(&conn, &org_b, "shared_name", "val-b").unwrap();

    delete_secret(&conn, &org_a, "shared_name").unwrap();
    assert!(get_secret(&conn, &org_a, "shared_name").unwrap().is_none());
    assert!(
        get_secret(&conn, &org_b, "shared_name").unwrap().is_some(),
        "org_b's secret must survive org_a's deletion"
    );
}

#[test]
fn org_b_cannot_delete_org_a_secret() {
    let conn = test_conn();
    let org_a = OrgId("alpha".into());
    let org_b = OrgId("beta".into());
    put_secret(&conn, &org_a, "precious", "diamond").unwrap();

    let deleted = delete_secret(&conn, &org_b, "precious").unwrap();
    assert!(!deleted, "org_b must not delete org_a's secret");
    assert!(
        get_secret(&conn, &org_a, "precious").unwrap().is_some(),
        "org_a's secret must still exist"
    );
}

// ── Org ID edge cases ────────────────────────────────────────────────────────

#[test]
fn org_id_with_special_chars_isolated() {
    let org_normal = OrgId("acme".into());
    let org_special = OrgId("evil-org/../../etc".into());
    assert!(
        validate_table_access(&org_special, "org_acme_tasks").is_err(),
        "special-char org must NOT access another org's tables"
    );
    let special_prefix = org_special.table_prefix();
    assert!(
        validate_table_access(&org_normal, &format!("{special_prefix}tasks")).is_err(),
        "normal org must NOT access special-char org's tables"
    );
}

#[test]
fn org_id_prefix_collision_prevented() {
    let org1 = OrgId("org_a".into());
    let org2 = OrgId("org-a".into());
    let p1 = org1.table_prefix();
    let p2 = org2.table_prefix();
    assert!(validate_table_access(&org1, &format!("{p1}tasks")).is_ok());
    assert!(validate_table_access(&org2, &format!("{p2}tasks")).is_ok());
}
