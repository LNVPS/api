use std::collections::BTreeMap;

const NEWEST_GUESSED_VERSION_APPLIED_IN_PROD: u64 = 20261201000000;

fn migration_versions() -> Vec<(u64, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".sql"))
        .map(|name| {
            let (version, rest) = name
                .split_once('_')
                .unwrap_or_else(|| panic!("{name} is not VERSION_description.sql"));
            assert!(
                version.len() == 14
                    && version.bytes().all(|b| b.is_ascii_digit())
                    && !rest.is_empty(),
                "{name} must be named YYYYMMDDHHMMSS_description.sql"
            );
            (version.parse().unwrap(), name)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn migration_versions_are_unique() {
    let mut seen: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (version, name) in migration_versions() {
        seen.entry(version).or_default().push(name);
    }
    let dupes: Vec<_> = seen.into_values().filter(|names| names.len() > 1).collect();
    assert!(dupes.is_empty(), "migrations share a version: {dupes:?}");
}

#[test]
fn new_migration_versions_are_real_times() {
    let guessed: Vec<_> = migration_versions()
        .into_iter()
        .filter(|(version, _)| {
            *version > NEWEST_GUESSED_VERSION_APPLIED_IN_PROD && version % 10_000 == 0
        })
        .map(|(_, name)| name)
        .collect();
    assert!(
        guessed.is_empty(),
        "these versions look made up, name migrations with `date -u +%Y%m%d%H%M%S`: {guessed:?}"
    );
}

#[test]
fn migrations_applied_in_prod_are_never_renamed_or_deleted() {
    let present: Vec<_> = migration_versions()
        .into_iter()
        .map(|(_, name)| name)
        .collect();
    let missing: Vec<_> = include_str!("migrations_applied_in_prod.txt")
        .lines()
        .filter(|name| !name.is_empty() && !present.iter().any(|p| p == name))
        .collect();
    assert!(
        missing.is_empty(),
        "migrations applied in production were renamed or deleted: {missing:?}"
    );
}

#[test]
fn migration_versions_are_valid_utc_times() {
    for (version, name) in migration_versions() {
        assert!(
            chrono::NaiveDateTime::parse_from_str(&version.to_string(), "%Y%m%d%H%M%S").is_ok(),
            "{name} does not start with a real YYYYMMDDHHMMSS time"
        );
    }
}
