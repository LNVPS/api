use std::sync::OnceLock;

use nostr::Keys;
use sqlx::Row;
use sqlx::mysql::MySqlPool;

// ---------------------------------------------------------------------------
// Per-run database isolation
// ---------------------------------------------------------------------------

/// Return the unique run ID for this test process.
///
/// Reads `LNVPS_E2E_RUN_ID` from the environment. If not set, generates a
/// timestamp-based ID once per process and caches it.
pub fn run_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        std::env::var("LNVPS_E2E_RUN_ID").unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_string()
        })
    })
}

/// Name of the per-run test database: `lnvps_e2e_{run_id}`.
pub fn test_db_name() -> String {
    format!("lnvps_e2e_{}", run_id())
}

/// Base URL for the database server without any database name.
/// Reads `LNVPS_DB_BASE_URL` (e.g. `mysql://root:root@localhost:3376`).
/// Falls back to stripping the path from `LNVPS_DB_URL` or using the
/// docker-compose default.
fn root_db_url() -> String {
    if let Ok(v) = std::env::var("LNVPS_DB_BASE_URL") {
        return v;
    }
    // Derive from LNVPS_DB_URL by dropping everything from the last '/'
    let full = std::env::var("LNVPS_DB_URL")
        .unwrap_or_else(|_| "mysql://root:root@localhost:3376/lnvps".to_string());
    // Strip the database name component (last '/...' segment)
    if let Some(idx) = full.rfind('/') {
        full[..idx].to_string()
    } else {
        full
    }
}

/// Full connection URL for the per-run test database.
fn db_url() -> String {
    format!("{}/{}", root_db_url(), test_db_name())
}

/// Create the per-run test database if it does not already exist.
pub async fn create_test_database() -> anyhow::Result<()> {
    // Connect to a neutral system database to issue CREATE DATABASE
    let root_url = format!("{}/mysql", root_db_url());
    let pool = MySqlPool::connect(&root_url).await?;
    let db_name = test_db_name();
    sqlx::query(&format!("CREATE DATABASE IF NOT EXISTS `{db_name}`"))
        .execute(&pool)
        .await?;
    pool.close().await;
    eprintln!("[e2e] Created test database: {db_name}");
    Ok(())
}

/// Drop the per-run test database.
pub async fn drop_test_database() -> anyhow::Result<()> {
    let root_url = format!("{}/mysql", root_db_url());
    let pool = MySqlPool::connect(&root_url).await?;
    let db_name = test_db_name();
    sqlx::query(&format!("DROP DATABASE IF EXISTS `{db_name}`"))
        .execute(&pool)
        .await?;
    pool.close().await;
    eprintln!("[e2e] Dropped test database: {db_name}");
    Ok(())
}

/// Ensure the test database has been created exactly once per process.
/// Returns the database name.
pub async fn ensure_test_database() -> anyhow::Result<String> {
    static CREATED: OnceLock<String> = OnceLock::new();
    if let Some(name) = CREATED.get() {
        return Ok(name.clone());
    }
    create_test_database().await?;
    let name = test_db_name();
    // Ignore error if another thread beat us to it
    let _ = CREATED.set(name.clone());
    Ok(name)
}

/// Connect to the per-run test database (creating it first if necessary).
pub async fn connect() -> anyhow::Result<MySqlPool> {
    ensure_test_database().await?;
    let pool = MySqlPool::connect(&db_url()).await?;
    Ok(pool)
}

/// Ensure a user exists for the given Nostr keys and return the user_id.
/// Uses the same INSERT IGNORE + SELECT pattern as the production `upsert_user`.
pub async fn ensure_user(pool: &MySqlPool, keys: &Keys) -> anyhow::Result<u64> {
    let pubkey = keys.public_key().to_bytes();

    let res: Option<(u64,)> =
        sqlx::query_as("INSERT IGNORE INTO users(pubkey, contact_nip17) VALUES(?, 1) RETURNING id")
            .bind(pubkey.as_slice())
            .fetch_optional(pool)
            .await?;

    match res {
        Some((id,)) => Ok(id),
        None => {
            let row = sqlx::query("SELECT id FROM users WHERE pubkey = ?")
                .bind(pubkey.as_slice())
                .fetch_one(pool)
                .await?;
            Ok(row.try_get::<u32, _>(0)? as u64)
        }
    }
}

/// Look up the role_id for a named role.
pub async fn get_role_id(pool: &MySqlPool, role_name: &str) -> anyhow::Result<u64> {
    let row = sqlx::query("SELECT id FROM admin_roles WHERE name = ?")
        .bind(role_name)
        .fetch_one(pool)
        .await?;
    Ok(row.try_get::<u64, _>(0)?)
}

/// Assign a role to a user (idempotent via INSERT IGNORE).
pub async fn assign_role(pool: &MySqlPool, user_id: u64, role_id: u64) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT IGNORE INTO admin_role_assignments(user_id, role_id, assigned_by) VALUES(?, ?, ?)",
    )
    .bind(user_id)
    .bind(role_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Ensure the user has the given role. Creates the user if needed.
/// Returns the user_id.
pub async fn ensure_user_with_role(
    pool: &MySqlPool,
    keys: &Keys,
    role_name: &str,
) -> anyhow::Result<u64> {
    let user_id = ensure_user(pool, keys).await?;
    let role_id = get_role_id(pool, role_name).await?;
    assign_role(pool, user_id, role_id).await?;
    Ok(user_id)
}

/// Remove all roles from a user.
pub async fn remove_all_roles(pool: &MySqlPool, user_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM admin_role_assignments WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete a VM and all its dependent rows from the database.
/// Used by E2E cleanup when the worker cannot reach a fake host.
///
/// Also removes the subscription and its payments that back this VM,
/// because all new VMs link to a `subscription_line_item` and expiry is
/// tracked in `subscription.expires` (not in `vm` directly).
pub async fn hard_delete_vm(pool: &MySqlPool, vm_id: u64) -> anyhow::Result<()> {
    // Resolve subscription_id via the line-item link before deleting the VM row.
    let sub_id: Option<u64> = sqlx::query_scalar(
        "SELECT sli.subscription_id \
         FROM vm v \
         INNER JOIN subscription_line_item sli ON sli.id = v.subscription_line_item_id \
         WHERE v.id = ?",
    )
    .bind(vm_id)
    .fetch_optional(pool)
    .await?;

    sqlx::query("DELETE FROM vm_ip_assignment WHERE vm_id = ?")
        .bind(vm_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM vm_history WHERE vm_id = ?")
        .bind(vm_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM vm WHERE id = ?")
        .bind(vm_id)
        .execute(pool)
        .await?;

    // Delete subscription rows that were linked to this VM (if any).
    if let Some(sid) = sub_id {
        hard_delete_subscription(pool, sid).await?;
    }

    Ok(())
}

/// Hard-delete a subscription and all its payments and line items.
///
/// Use this when the admin API soft-deletes subscriptions or when the
/// lifecycle test needs to clean up a subscription that was created via
/// the admin API or the subscription endpoints directly.
pub async fn hard_delete_subscription(pool: &MySqlPool, sub_id: u64) -> anyhow::Result<()> {
    // Payments reference the subscription; delete them first.
    sqlx::query("DELETE FROM subscription_payment WHERE subscription_id = ?")
        .bind(sub_id)
        .execute(pool)
        .await?;
    // Line items cascade-delete from the subscription in production (ON DELETE
    // CASCADE), but we delete explicitly here to be safe across all DB configs.
    sqlx::query("DELETE FROM subscription_line_item WHERE subscription_id = ?")
        .bind(sub_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM subscription WHERE id = ?")
        .bind(sub_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete a host and its disks from the database.
pub async fn hard_delete_host(pool: &MySqlPool, host_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM vm_host_disk WHERE host_id = ?")
        .bind(host_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM vm_host WHERE id = ?")
        .bind(host_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete a region (admin DELETE only soft-deletes via `enabled = false`).
pub async fn hard_delete_region(pool: &MySqlPool, region_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM vm_host_region WHERE id = ?")
        .bind(region_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete custom pricing, its disk rows, and any custom templates referencing it.
pub async fn hard_delete_custom_pricing(pool: &MySqlPool, pricing_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM vm_custom_template WHERE pricing_id = ?")
        .bind(pricing_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM vm_custom_pricing_disk WHERE pricing_id = ?")
        .bind(pricing_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM vm_custom_pricing WHERE id = ?")
        .bind(pricing_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete an IP range.
pub async fn hard_delete_ip_range(pool: &MySqlPool, ip_range_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM ip_range WHERE id = ?")
        .bind(ip_range_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete a VM template.
pub async fn hard_delete_vm_template(pool: &MySqlPool, template_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM vm_template WHERE id = ?")
        .bind(template_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete an OS image.
pub async fn hard_delete_os_image(pool: &MySqlPool, image_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM vm_os_image WHERE id = ?")
        .bind(image_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete a cost plan.
pub async fn hard_delete_cost_plan(pool: &MySqlPool, cost_plan_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM vm_cost_plan WHERE id = ?")
        .bind(cost_plan_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete a company.
pub async fn hard_delete_company(pool: &MySqlPool, company_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM company WHERE id = ?")
        .bind(company_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Backdate `subscription.created` by the given number of hours so that `check_vms`
/// considers the VM eligible for unpaid-VM cleanup (threshold: 1 hour).
pub async fn backdate_vm_created(pool: &MySqlPool, vm_id: u64, hours: u32) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE subscription s \
         INNER JOIN subscription_line_item sli ON sli.subscription_id = s.id \
         INNER JOIN vm v ON v.subscription_line_item_id = sli.id \
         SET s.created = DATE_SUB(NOW(), INTERVAL ? HOUR) \
         WHERE v.id = ?",
    )
    .bind(hours)
    .bind(vm_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Set `subscription.expires` to a given number of seconds in the past so that
/// `check_subscriptions` considers it expired (or within the grace period).
///
/// Pass `seconds_ago = 0` to set it to exactly `NOW()` (boundary).
pub async fn expire_subscription(
    pool: &MySqlPool,
    sub_id: u64,
    seconds_ago: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE subscription SET expires = DATE_SUB(NOW(), INTERVAL ? SECOND) WHERE id = ?",
    )
    .bind(seconds_ago)
    .bind(sub_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a referral directly (bypasses lightning address validation).
pub async fn insert_referral(
    pool: &MySqlPool,
    user_id: u64,
    code: &str,
    lightning_address: Option<&str>,
) -> anyhow::Result<u64> {
    let res: (u64,) = sqlx::query_as(
        "INSERT INTO referral (user_id, code, mode, address) VALUES (?, ?, 0, ?) RETURNING id",
    )
    .bind(user_id)
    .bind(code)
    .bind(lightning_address)
    .fetch_one(pool)
    .await?;
    Ok(res.0)
}

/// Update a referral's payout `mode` (0=lightning_address, 1=nwc, 3=on_chain)
/// and `address` directly (bypasses API validation).
pub async fn set_referral_mode_address(
    pool: &MySqlPool,
    referral_id: u64,
    mode: u16,
    address: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE referral SET mode = ?, address = ? WHERE id = ?")
        .bind(mode)
        .bind(address)
        .bind(referral_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Read a referral's payouts as `(amount, fee, is_paid, outpoint)` rows,
/// most-recent first.
pub async fn list_referral_payouts(
    pool: &MySqlPool,
    referral_id: u64,
) -> anyhow::Result<Vec<(u64, u64, bool, Option<String>)>> {
    let rows = sqlx::query(
        "SELECT amount, fee, is_paid, outpoint FROM referral_payout \
         WHERE referral_id = ? ORDER BY created DESC, id DESC",
    )
    .bind(referral_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.try_get::<u64, _>(0).unwrap_or(0),
                r.try_get::<u64, _>(1).unwrap_or(0),
                r.try_get::<i8, _>(2).map(|v| v != 0).unwrap_or(false),
                r.try_get::<Option<String>, _>(3).unwrap_or(None),
            )
        })
        .collect())
}

/// The FK ids `(host_id, image_id, template_id, disk_id)` of an existing VM, so
/// seeded referred VMs can reuse valid references.
pub async fn vm_fk_ids(pool: &MySqlPool, vm_id: u64) -> anyhow::Result<(u64, u64, u64, u64)> {
    let row = sqlx::query("SELECT host_id, image_id, template_id, disk_id FROM vm WHERE id = ?")
        .bind(vm_id)
        .fetch_one(pool)
        .await?;
    Ok((
        row.try_get::<u64, _>(0)?,
        row.try_get::<u64, _>(1)?,
        row.try_get::<u64, _>(2)?,
        row.try_get::<u64, _>(3)?,
    ))
}

/// Seed a referrer enrolled in `mode` with `address`, plus a referred VM whose
/// first paid BTC payment earns them exactly `commission_sats` of commission
/// (via a 100% per-referrer rate on a `commission_sats`-sized payment). FK ids
/// are reused from `fk_from_vm`. Returns `(referral_id, referred_vm_id)`.
#[allow(clippy::too_many_arguments)]
pub async fn seed_referrer_with_commission(
    pool: &MySqlPool,
    referrer_user_id: u64,
    referred_user_id: u64,
    code: &str,
    mode: u16,
    address: Option<&str>,
    commission_sats: u64,
    fk_from_vm: u64,
) -> anyhow::Result<(u64, u64)> {
    let (host_id, image_id, template_id, disk_id) = vm_fk_ids(pool, fk_from_vm).await?;

    // Referrer enrollment with a 100% override so commission == payment amount.
    let (referral_id,): (u64,) = sqlx::query_as(
        "INSERT INTO referral (user_id, code, mode, address, referral_rate) \
         VALUES (?, ?, ?, ?, 100) RETURNING id",
    )
    .bind(referrer_user_id)
    .bind(code)
    .bind(mode)
    .bind(address)
    .fetch_one(pool)
    .await?;

    // A BTC subscription + VPS line item + one paid payment == the referred VM's
    // first payment that earns commission.
    let (sub_id,): (u64,) = sqlx::query_as(
        "INSERT INTO subscription (user_id, company_id, name, description, created, expires, \
             is_active, is_setup, currency, interval_amount, interval_type, setup_fee, \
             auto_renewal_enabled, external_id) \
         VALUES (?, (SELECT MIN(id) FROM company), 'e2e-referred', NULL, NOW(), NULL, 1, 1, \
             'BTC', 1, 0, 0, 0, NULL) RETURNING id",
    )
    .bind(referred_user_id)
    .fetch_one(pool)
    .await?;

    let amount_msat = commission_sats * 1000;
    let (li_id,): (u64,) = sqlx::query_as(
        "INSERT INTO subscription_line_item (subscription_id, subscription_type, name, \
             description, amount, setup_amount, configuration) \
         VALUES (?, 3, 'vm', NULL, ?, 0, NULL) RETURNING id",
    )
    .bind(sub_id)
    .bind(amount_msat)
    .fetch_one(pool)
    .await?;

    let (vm_id,): (u64,) = sqlx::query_as(
        "INSERT INTO vm(host_id,user_id,image_id,template_id,custom_template_id,\
             subscription_line_item_id,ssh_key_id,disk_id,mac_address,ref_code) \
         VALUES (?, ?, ?, ?, NULL, ?, NULL, ?, ?, ?) RETURNING id",
    )
    .bind(host_id)
    .bind(referred_user_id)
    .bind(image_id)
    .bind(template_id)
    .bind(li_id)
    .bind(disk_id)
    .bind(format!(
        "00:00:00:00:{:02x}:{:02x}",
        referral_id & 0xff,
        vm_mac_suffix(code)
    ))
    .bind(code)
    .fetch_one(pool)
    .await?;

    // Random 32-byte payment id; is_paid=1 BTC payment.
    let payment_id: [u8; 32] = rand_bytes32();
    sqlx::query(
        "INSERT INTO subscription_payment (id, subscription_id, user_id, created, expires, amount, \
             currency, payment_method, payment_type, external_data, external_id, is_paid, rate, \
             tax, processing_fee, time_value, metadata, paid_at, tax_rate, tax_country_code, \
             tax_treatment, tax_evidence, tax_breakdown) \
         VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), ?, 'BTC', 0, 0, '', NULL, 1, \
             1.0, 0, 0, 2592000, NULL, NOW(), NULL, NULL, NULL, NULL, NULL)",
    )
    .bind(payment_id.as_slice())
    .bind(sub_id)
    .bind(referred_user_id)
    .bind(amount_msat)
    .execute(pool)
    .await?;

    Ok((referral_id, vm_id))
}

fn vm_mac_suffix(code: &str) -> u8 {
    code.bytes().fold(0u8, |a, b| a.wrapping_add(b))
}

fn rand_bytes32() -> [u8; 32] {
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

/// Hard-delete a referral and its payouts.
pub async fn hard_delete_referral(pool: &MySqlPool, referral_id: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM referral_payout WHERE referral_id = ?")
        .bind(referral_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM referral WHERE id = ?")
        .bind(referral_id)
        .execute(pool)
        .await?;
    Ok(())
}
