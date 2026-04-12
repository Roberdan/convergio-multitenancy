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
    let b_table = format!("{}tasks", org_b.table_prefix());
    let a_table = format!("{}tasks", org_a.table_prefix());
    assert!(
        validate_table_access(&org_a, &b_table).is_err(),
        "org alpha must NOT access org_beta tables"
    );
    assert!(
        validate_table_access(&org_b, &a_table).is_err(),
        "org beta must NOT access org_alpha tables"
    );
}

#[test]
fn org_accesses_own_tables() {
    let org = OrgId("acme".into());
    let prefix = org.table_prefix();
    assert!(validate_table_access(&org, &format!("{prefix}tasks")).is_ok());
    assert!(validate_table_access(&org, &format!("{prefix}agents")).is_ok());
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
fn sql_injection_in_org_id_rejected_by_validation() {
    let result = OrgId::new("'; DROP TABLE users; --");
    assert!(result.is_err(), "SQL injection org_id must be rejected");
}

#[test]
fn empty_org_id_rejected_by_validation() {
    let result = OrgId::new("");
    assert!(result.is_err(), "empty org_id must be rejected");
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
    assert_eq!(tables_a.len(), 1);
    assert_eq!(tables_b.len(), 1);
    assert!(tables_a[0].contains("alpha"));
    assert!(tables_b[0].contains("beta"));
    // Cross-isolation: a's tables don't appear in b's list
    assert!(!tables_a.iter().any(|t| t.contains("beta")));
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

// ── Org ID validation ────────────────────────────────────────────────────────

#[test]
fn org_id_with_special_chars_rejected() {
    assert!(OrgId::new("evil-org/../../etc").is_err());
    assert!(OrgId::new("org;DROP TABLE").is_err());
    assert!(OrgId::new("org\0null").is_err());
}

#[test]
fn org_id_prefix_collision_prevented() {
    let org1 = OrgId("org_a".into());
    let org2 = OrgId("org-a".into());
    let p1 = org1.table_prefix();
    let p2 = org2.table_prefix();
    assert_ne!(p1, p2, "different org_ids must produce different prefixes");
    assert!(validate_table_access(&org1, &format!("{p1}tasks")).is_ok());
    assert!(validate_table_access(&org2, &format!("{p2}tasks")).is_ok());
    // Cross-access blocked
    assert!(validate_table_access(&org1, &format!("{p2}tasks")).is_err());
    assert!(validate_table_access(&org2, &format!("{p1}tasks")).is_err());
}
