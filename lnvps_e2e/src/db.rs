use nostr::Keys;
use sqlx::Row;
use sqlx::mysql::MySqlPool;

/// Default database URL for local development (matches docker-compose).
fn db_url() -> String {
    std::env::var("LNVPS_DB_URL")
        .unwrap_or_else(|_| "mysql://root:root@localhost:3376/lnvps".to_string())
}

/// Connect to the database.
pub async fn connect() -> anyhow::Result<MySqlPool> {
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
pub async fn hard_delete_vm(pool: &MySqlPool, vm_id: u64) -> anyhow::Result<()> {
    // Delete in dependency order
    sqlx::query("DELETE FROM vm_payment WHERE vm_id = ?")
        .bind(vm_id)
        .execute(pool)
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

/// Insert a referral directly (bypasses lightning address validation).
pub async fn insert_referral(
    pool: &MySqlPool,
    user_id: u64,
    code: &str,
    lightning_address: Option<&str>,
) -> anyhow::Result<u64> {
    let res: (u64,) = sqlx::query_as(
        "INSERT INTO referral (user_id, code, use_nwc, lightning_address) VALUES (?, ?, 0, ?) RETURNING id",
    )
    .bind(user_id)
    .bind(code)
    .bind(lightning_address)
    .fetch_one(pool)
    .await?;
    Ok(res.0)
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
