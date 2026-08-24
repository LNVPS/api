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

/// How many times `hard_delete_vm` retries a foreign-key failure before giving up.
const HARD_DELETE_RETRIES: u32 = 20;

/// MySQL error 1451: cannot delete a parent row, a child row still references it.
fn is_fk_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
        .is_some_and(|e| e.number() == 1451)
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

    // Traffic rows need no cleanup here: their FK cascades on the VM delete
    // below, which is exactly what this teardown is asserting still works.

    // The worker may still be writing history for this VM while teardown runs,
    // which re-parents a `vm_history` row between the child delete and the
    // parent delete and fails the FK. Retry the pair; a handler that is mid
    // flight finishes well inside this window.
    let mut attempt = 0;
    loop {
        sqlx::query("DELETE FROM vm_history WHERE vm_id = ?")
            .bind(vm_id)
            .execute(pool)
            .await?;
        match sqlx::query("DELETE FROM vm WHERE id = ?")
            .bind(vm_id)
            .execute(pool)
            .await
        {
            Ok(_) => break,
            Err(e) if is_fk_violation(&e) && attempt < HARD_DELETE_RETRIES => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

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
    sqlx::query("DELETE FROM region WHERE id = ?")
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

/// Hard-delete a company's discounts and their redemptions.
///
/// Discounts are company-scoped with a real FK, so they must go before the
/// company does; the redemption rows reference the discount in turn.
pub async fn hard_delete_company_discounts(
    pool: &MySqlPool,
    company_id: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        "DELETE FROM discount_redemption WHERE discount_id IN \
         (SELECT id FROM discount WHERE company_id = ?)",
    )
    .bind(company_id)
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM discount WHERE company_id = ?")
        .bind(company_id)
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

/// Write a VM's captured SSH host keys directly, standing in for the worker's
/// scan of the guest (which needs a real booted VM).
pub async fn set_vm_ssh_host_keys(pool: &MySqlPool, vm_id: u64, keys: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE vm SET ssh_host_keys = ? WHERE id = ?")
        .bind(keys)
        .bind(vm_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Book traffic for a VM directly, standing in for the worker's sampling of
/// hypervisor counters (which needs a real running VM on a reachable host).
pub async fn add_vm_traffic(
    pool: &MySqlPool,
    vm_id: u64,
    day: chrono::NaiveDate,
    bytes_in: u64,
    bytes_out: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO vm_traffic_daily(vm_id, day, bytes_in, bytes_out) VALUES(?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE bytes_in = bytes_in + VALUES(bytes_in), \
         bytes_out = bytes_out + VALUES(bytes_out)",
    )
    .bind(vm_id)
    .bind(day)
    .bind(bytes_in)
    .bind(bytes_out)
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

/// Read a referral's payouts as `(amount, fee, is_paid, output)` rows,
/// most-recent first. `output` is a BOLT11 invoice for Lightning payouts or the
/// on-chain outpoint (`"{txid}:{vout}"`) for on-chain payouts.
pub async fn list_referral_payouts(
    pool: &MySqlPool,
    referral_id: u64,
) -> anyhow::Result<Vec<(u64, u64, bool, Option<String>)>> {
    let rows = sqlx::query(
        "SELECT amount, fee, is_paid, output FROM referral_payout \
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
    .bind(random_mac())
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

/// Seed a full app deployment (catalog app + cluster + subscription/line-item +
/// deployment) owned by `user_id`. Returns `(app_id, cluster_id, deployment_id)`.
/// Used to exercise the read-only customer app endpoints before the ordering
/// flow exists.
pub async fn seed_app_deployment(
    pool: &MySqlPool,
    user_id: u64,
    name: &str,
) -> anyhow::Result<(u64, u64, u64)> {
    let suffix = hex::encode(&rand_bytes32()[..4]);
    let slug = format!("{name}-{suffix}");

    let (app_id,): (u64,) = sqlx::query_as(
        "INSERT INTO app (name, display_name, description, icon, category, compose, amount, \
             currency, interval_amount, interval_type, setup_amount, enabled) \
         VALUES (?, 'E2E App', NULL, NULL, 'Nostr relay', 'services: {}', 1000, 'USD', 1, 1, 0, 1) \
         RETURNING id",
    )
    .bind(&slug)
    .fetch_one(pool)
    .await?;

    let (cluster_id,): (u64,) = sqlx::query_as(
        "INSERT INTO app_cluster (name, region_id, ingress_domain, enabled) \
         VALUES (?, ?, 'apps.e2e.example.com', 1) RETURNING id",
    )
    .bind(&slug)
    // Own enabled region — see seed_enabled_region.
    .bind(seed_enabled_region(pool, &format!("e2e-app-{slug}")).await?)
    .fetch_one(pool)
    .await?;

    let (sub_id,): (u64,) = sqlx::query_as(
        "INSERT INTO subscription (user_id, company_id, name, description, created, expires, \
             is_active, is_setup, currency, interval_amount, interval_type, setup_fee, \
             auto_renewal_enabled, external_id) \
         VALUES (?, (SELECT MIN(id) FROM company), 'e2e-app-sub', NULL, NOW(), NULL, 1, 1, \
             'USD', 1, 1, 0, 0, NULL) RETURNING id",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // subscription_type = 4 (App)
    let (li_id,): (u64,) = sqlx::query_as(
        "INSERT INTO subscription_line_item (subscription_id, subscription_type, name, \
             description, amount, setup_amount, configuration) \
         VALUES (?, 4, 'app', NULL, 1000, 0, NULL) RETURNING id",
    )
    .bind(sub_id)
    .fetch_one(pool)
    .await?;

    let (dep_id,): (u64,) = sqlx::query_as(
        "INSERT INTO app_deployment (user_id, app_id, cluster_id, subscription_line_item_id, \
             name, namespace, hostname, config, desired_state, status, status_message) \
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 0, 0, NULL) RETURNING id",
    )
    .bind(user_id)
    .bind(app_id)
    .bind(cluster_id)
    .bind(li_id)
    .bind(name)
    .bind(&slug)
    .fetch_one(pool)
    .await?;

    Ok((app_id, cluster_id, dep_id))
}

/// Seed an enabled catalog app (small footprint) + a cluster with capacity in an
/// existing region. Returns `(app_id, cluster_id, region_id)`. Used to exercise
/// the customer ordering flow.
/// Create an enabled region (under the lowest-id company) and return its id.
///
/// App tests seed their own region instead of reusing whatever is already in the
/// database. Regions are created and soft-deleted (`enabled = false`) by other
/// tests and the base dataset has no enabled region of its own, so picking one
/// by `MIN(id)` either lands on a disabled leftover — and
/// `GET /api/v1/apps/{id}/regions` only surfaces enabled regions, so the seeded
/// cluster never shows as deployable — or finds nothing at all and inserts NULL.
async fn seed_enabled_region(pool: &MySqlPool, name: &str) -> anyhow::Result<u64> {
    let (company_id,): (u64,) = sqlx::query_as("SELECT MIN(id) FROM company")
        .fetch_one(pool)
        .await?;
    let (region_id,): (u64,) = sqlx::query_as(
        "INSERT INTO region (name, enabled, company_id) VALUES (?, 1, ?) RETURNING id",
    )
    .bind(name)
    .bind(company_id)
    .fetch_one(pool)
    .await?;
    Ok(region_id)
}

pub async fn seed_app_and_cluster(pool: &MySqlPool) -> anyhow::Result<(u64, u64, u64)> {
    seed_app_and_cluster_with_capacity(pool, 8000, 8589934592, 107374182400).await
}

/// Same as [`seed_app_and_cluster`] but with an explicit cluster capacity, so a
/// test can size the cluster against the app's footprint (250m / 256Mi / 0) and
/// exercise the admission path when it is full.
pub async fn seed_app_and_cluster_with_capacity(
    pool: &MySqlPool,
    capacity_cpu_milli: u64,
    capacity_memory_bytes: u64,
    capacity_storage_bytes: u64,
) -> anyhow::Result<(u64, u64, u64)> {
    let suffix = hex::encode(&rand_bytes32()[..4]);
    let region_id = seed_enabled_region(pool, &format!("e2e-apps-{suffix}")).await?;

    // App with a real (small) footprint and a valid single-service compose.
    let (app_id,): (u64,) = sqlx::query_as(
        "INSERT INTO app (name, display_name, description, icon, category, compose, amount, \
             currency, interval_amount, interval_type, setup_amount, enabled, cpu_milli, \
             memory_bytes, storage_bytes) \
         VALUES (?, 'E2E Orderable', NULL, NULL, 'Nostr relay', \
             'services:\\n  web:\\n    image: example/web:latest\\n    ports:\\n      - { name: http, container: 80, protocol: http, expose: ingress }\\nconfig:\\n  - { name: title, type: string, default: \"hi\" }\\n', \
             1000, 'USD', 1, 1, 0, 1, 250, 268435456, 0) RETURNING id",
    )
    .bind(format!("orderable-{suffix}"))
    .fetch_one(pool)
    .await?;

    let (cluster_id,): (u64,) = sqlx::query_as(
        "INSERT INTO app_cluster (name, region_id, ingress_domain, enabled, capacity_cpu_milli, \
             capacity_memory_bytes, capacity_storage_bytes) \
         VALUES (?, ?, 'apps.e2e.example.com', 1, ?, ?, ?) RETURNING id",
    )
    .bind(format!("ordercluster-{suffix}"))
    .bind(region_id)
    .bind(capacity_cpu_milli)
    .bind(capacity_memory_bytes)
    .bind(capacity_storage_bytes)
    .fetch_one(pool)
    .await?;

    Ok((app_id, cluster_id, region_id))
}

/// Seed an orderable app whose `config:` declares a typed field and a
/// pattern-constrained one, for the order-time validation in issue #271.
///
/// Returns `(app_id, region_id)`.
pub async fn seed_app_with_typed_config(pool: &MySqlPool) -> anyhow::Result<(u64, u64)> {
    let suffix = hex::encode(&rand_bytes32()[..4]);
    let region_id = seed_enabled_region(pool, &format!("e2e-typed-{suffix}")).await?;
    let compose = "services:\n  web:\n    image: example/web:latest\n    ports:\n      \
         - { name: http, container: 80, protocol: http, expose: ingress }\n    env:\n      \
         COUNT: ${count}\n      OWNER: ${owner_npub}\n\
         config:\n  - { name: count, label: \"Count\", type: int, default: \"1\" }\n  \
         - { name: owner_npub, label: \"Owner npub\", type: string, required: true, \
         pattern: \"npub1[02-9ac-hj-np-z]{58}\" }\n";
    let (app_id,): (u64,) = sqlx::query_as(
        "INSERT INTO app (name, display_name, description, icon, category, compose, amount, \
             currency, interval_amount, interval_type, setup_amount, enabled, cpu_milli, \
             memory_bytes, storage_bytes) \
         VALUES (?, 'E2E Typed Config', NULL, NULL, 'Nostr relay', ?, \
             1000, 'USD', 1, 1, 0, 1, 250, 268435456, 0) RETURNING id",
    )
    .bind(format!("typed-{suffix}"))
    .bind(compose)
    .fetch_one(pool)
    .await?;

    sqlx::query(
        "INSERT INTO app_cluster (name, region_id, ingress_domain, enabled, capacity_cpu_milli, \
             capacity_memory_bytes, capacity_storage_bytes) \
         VALUES (?, ?, 'apps.e2e.example.com', 1, 100000, 100000000000, 100000000000)",
    )
    .bind(format!("typedcluster-{suffix}"))
    .bind(region_id)
    .execute(pool)
    .await?;

    Ok((app_id, region_id))
}

/// Seed an enabled app whose compose declares one labelled and one unlabelled
/// volume, for the per-volume storage breakdown (issue #260). Returns its id.
///
/// `storage_bytes` is the sum of the two volumes, matching what the admin API
/// computes on create, so the response's breakdown can be checked against the
/// total a client already renders.
pub async fn seed_app_with_labelled_volumes(pool: &MySqlPool) -> anyhow::Result<u64> {
    let suffix = hex::encode(&rand_bytes32()[..4]);
    let compose = "services:\n  relay:\n    image: example/relay:latest\n    ports:\n               - { name: http, container: 80, protocol: http, expose: ingress }\n    volumes:\n               - { name: db, path: /app/db, size: 10Gi, label: events }\n               - { name: cache, path: /app/cache, size: 1Gi }\n";
    let (app_id,): (u64,) = sqlx::query_as(
        "INSERT INTO app (name, display_name, description, icon, category, compose, amount, \
             currency, interval_amount, interval_type, setup_amount, enabled, cpu_milli, \
             memory_bytes, storage_bytes) \
         VALUES (?, 'E2E Volumes', NULL, NULL, 'Nostr relay', ?, \
             1000, 'USD', 1, 1, 0, 1, 250, 268435456, ?) RETURNING id",
    )
    .bind(format!("volumes-{suffix}"))
    .bind(compose)
    .bind(11u64 * 1024 * 1024 * 1024)
    .fetch_one(pool)
    .await?;
    Ok(app_id)
}

fn random_mac() -> String {
    let b = rand_bytes32();
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4]
    )
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

/// Identifiers for a fully-seeded standalone VM, for cleanup.
pub struct SeededVm {
    pub vm_id: u64,
    pub subscription_id: u64,
    pub host_id: u64,
    pub disk_id: u64,
    pub template_id: u64,
    pub cost_plan_id: u64,
    pub image_id: u64,
    pub region_id: u64,
    pub company_id: u64,
}

/// Seed a complete VM owned by `user_id`, building the whole infrastructure
/// chain from scratch (company → region → cost plan → image → host → disk →
/// template → subscription → line item → vm).
///
/// Unlike [`seed_referrer_with_commission`] this borrows no foreign keys from an
/// existing VM, so a test using it does not depend on the lifecycle test having
/// run. `ssh_host_keys` is stored on the VM verbatim, which lets a test plant a
/// recognisable sentinel and assert it never leaks.
pub async fn seed_standalone_vm(
    pool: &MySqlPool,
    user_id: u64,
    label: &str,
    ssh_host_keys: &str,
) -> anyhow::Result<SeededVm> {
    let (company_id,): (u64,) =
        sqlx::query_as("INSERT INTO company (name, email) VALUES (?, ?) RETURNING id")
            .bind(format!("{label}-co"))
            .bind(format!("{label}@example.com"))
            .fetch_one(pool)
            .await?;

    let (region_id,): (u64,) = sqlx::query_as(
        "INSERT INTO region (name, enabled, company_id) VALUES (?, 1, ?) RETURNING id",
    )
    .bind(format!("{label}-region"))
    .bind(company_id)
    .fetch_one(pool)
    .await?;

    let (cost_plan_id,): (u64,) = sqlx::query_as(
        "INSERT INTO vm_cost_plan (name, amount, currency, interval_amount, interval_type) \
         VALUES (?, 1000, 'BTC', 1, 0) RETURNING id",
    )
    .bind(format!("{label}-plan"))
    .fetch_one(pool)
    .await?;

    let (image_id,): (u64,) = sqlx::query_as(
        "INSERT INTO vm_os_image (distribution, flavour, version, enabled, release_date, url) \
         VALUES (0, 'server', ?, 1, NOW(), 'https://example.com/img.qcow2') RETURNING id",
    )
    .bind(format!("{label}-1.0"))
    .fetch_one(pool)
    .await?;

    let (host_id,): (u64,) = sqlx::query_as(
        "INSERT INTO vm_host (kind, region_id, name, ip, cpu, memory, enabled, api_token) \
         VALUES (0, ?, ?, 'https://127.0.0.1:8006', 8, 68719476736, 1, ?) RETURNING id",
    )
    .bind(region_id)
    .bind(format!("{label}-host"))
    .bind(format!("{label}-HOST-API-TOKEN"))
    .fetch_one(pool)
    .await?;

    let (disk_id,): (u64,) = sqlx::query_as(
        "INSERT INTO vm_host_disk (host_id, name, size, kind, interface, enabled) \
         VALUES (?, 'local', 1099511627776, 0, 0, 1) RETURNING id",
    )
    .bind(host_id)
    .fetch_one(pool)
    .await?;

    let (template_id,): (u64,) = sqlx::query_as(
        "INSERT INTO vm_template (name, enabled, cpu, memory, disk_size, disk_type, \
             disk_interface, cost_plan_id, region_id) \
         VALUES (?, 1, 2, 2147483648, 21474836480, 0, 0, ?, ?) RETURNING id",
    )
    .bind(format!("{label}-template"))
    .bind(cost_plan_id)
    .bind(region_id)
    .fetch_one(pool)
    .await?;

    let (subscription_id,): (u64,) = sqlx::query_as(
        "INSERT INTO subscription (user_id, company_id, name, description, created, expires, \
             is_active, is_setup, currency, interval_amount, interval_type, setup_fee, \
             auto_renewal_enabled, external_id) \
         VALUES (?, ?, ?, NULL, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), 1, 1, 'BTC', 1, 0, 0, 0, NULL) \
         RETURNING id",
    )
    .bind(user_id)
    .bind(company_id)
    .bind(format!("{label}-sub"))
    .fetch_one(pool)
    .await?;

    let (li_id,): (u64,) = sqlx::query_as(
        "INSERT INTO subscription_line_item (subscription_id, subscription_type, name, \
             description, amount, setup_amount, configuration) \
         VALUES (?, 3, 'vm', NULL, 1000, 0, NULL) RETURNING id",
    )
    .bind(subscription_id)
    .fetch_one(pool)
    .await?;

    let (vm_id,): (u64,) = sqlx::query_as(
        "INSERT INTO vm(host_id,user_id,image_id,template_id,custom_template_id,\
             subscription_line_item_id,ssh_key_id,disk_id,mac_address,ssh_host_keys,ref_code) \
         VALUES (?, ?, ?, ?, NULL, ?, NULL, ?, ?, ?, NULL) RETURNING id",
    )
    .bind(host_id)
    .bind(user_id)
    .bind(image_id)
    .bind(template_id)
    .bind(li_id)
    .bind(disk_id)
    .bind(random_mac())
    .bind(ssh_host_keys)
    .fetch_one(pool)
    .await?;

    Ok(SeededVm {
        vm_id,
        subscription_id,
        host_id,
        disk_id,
        template_id,
        cost_plan_id,
        image_id,
        region_id,
        company_id,
    })
}

/// Tear down everything [`seed_standalone_vm`] created, innermost first.
pub async fn hard_delete_seeded_vm(pool: &MySqlPool, seeded: &SeededVm) -> anyhow::Result<()> {
    hard_delete_vm(pool, seeded.vm_id).await?;
    hard_delete_subscription(pool, seeded.subscription_id).await?;
    hard_delete_vm_template(pool, seeded.template_id).await?;
    sqlx::query("DELETE FROM vm_host_disk WHERE id = ?")
        .bind(seeded.disk_id)
        .execute(pool)
        .await?;
    hard_delete_host(pool, seeded.host_id).await?;
    hard_delete_os_image(pool, seeded.image_id).await?;
    hard_delete_cost_plan(pool, seeded.cost_plan_id).await?;
    hard_delete_region(pool, seeded.region_id).await?;
    hard_delete_company_discounts(pool, seeded.company_id).await?;
    hard_delete_company(pool, seeded.company_id).await?;
    Ok(())
}
