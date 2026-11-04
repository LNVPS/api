use crate::NetworkProvisioner;
use anyhow::Result;
use chrono::{DateTime, Datelike, TimeZone, Utc};
use lnvps_db::{
    IpOrder, IpOrderState, IpProvider, IpProviderRegion, IpWhenNoIp, LNVpsDb, VmIpWait,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpSale {
    InStock,
    WaitForIp,
    OutOfCapacity(String),
}

pub fn month_start(now: DateTime<Utc>) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .unwrap_or(now)
}

pub async fn free_ip4(db: &dyn LNVpsDb, region_id: u64) -> Result<u64> {
    let mut free = 0;
    for range in db.list_ip_range_in_region(region_id).await? {
        let used = db.list_vm_ip_assignments_in_range(range.id).await?.len() as u64;
        free += NetworkProvisioner::count_available_ips(&range, used).unwrap_or(0);
    }
    Ok(free)
}

pub fn waiting_ip4(waits: &[VmIpWait], before: Option<&VmIpWait>) -> u64 {
    waits
        .iter()
        .filter(|w| match before {
            Some(b) => w.vm_id != b.vm_id && (w.created, w.id) < (b.created, b.id),
            None => true,
        })
        .map(|w| w.ip4_needed as u64)
        .sum()
}

pub fn order_supply(o: &IpOrder) -> u64 {
    if o.prefix_len == 32 {
        o.quantity as u64
    } else {
        (1u64 << (32 - o.prefix_len.min(32))).saturating_sub(3) * o.quantity as u64
    }
}

pub async fn region_rule(
    db: &dyn LNVpsDb,
    region_id: u64,
) -> Result<Option<(IpProvider, IpProviderRegion)>> {
    for rule in db.list_ip_provider_regions(None, Some(region_id)).await? {
        if !rule.enabled || rule.when_no_ip != IpWhenNoIp::OrderAndWait {
            continue;
        }
        let provider = db.get_ip_provider(rule.provider_id).await?;
        if provider.enabled {
            return Ok(Some((provider, rule)));
        }
    }
    Ok(None)
}

pub async fn in_flight_orders(
    db: &dyn LNVpsDb,
    region_id: u64,
    provider: &str,
) -> Result<Vec<IpOrder>> {
    let (orders, _) = db.list_ip_orders(None, Some(region_id), 1000, 0).await?;
    Ok(orders
        .into_iter()
        .filter(|o| o.provider == provider && o.state.is_in_flight())
        .collect())
}

fn out_of_capacity(detail: &str) -> IpSale {
    IpSale::OutOfCapacity(format!(
        "This region is out of capacity right now{detail}. Please pick another region or try again later."
    ))
}

pub async fn sale_decision(db: &dyn LNVpsDb, region_id: u64, ip4_needed: u16) -> Result<IpSale> {
    if ip4_needed == 0 {
        return Ok(IpSale::InStock);
    }
    let waits = db.list_vm_ip_waits(Some(region_id)).await?;
    let free = free_ip4(db, region_id).await?;
    let demand = waiting_ip4(&waits, None) + ip4_needed as u64;
    if free >= demand {
        return Ok(IpSale::InStock);
    }
    let Some((provider, rule)) = region_rule(db, region_id).await? else {
        return Ok(out_of_capacity(""));
    };
    if rule.sell_without_capacity {
        return Ok(IpSale::WaitForIp);
    }
    if provider.approval_required {
        return Ok(out_of_capacity(" (more addresses need approval)"));
    }
    let in_flight = in_flight_orders(db, region_id, &provider.name).await?;
    if in_flight
        .iter()
        .any(|o| o.state == IpOrderState::AwaitingApproval)
    {
        return Ok(out_of_capacity(" (more addresses are awaiting approval)"));
    }
    let supply: u64 = in_flight.iter().map(order_supply).sum();
    if free + supply >= demand {
        return Ok(IpSale::WaitForIp);
    }
    let spent = db
        .sum_ip_order_cost_since(month_start(Utc::now()), &provider.currency)
        .await?;
    let (orders, _) = db.list_ip_orders(None, Some(region_id), 50, 0).await?;
    let unit_cost = orders
        .iter()
        .find(|o| o.provider == provider.name && o.cost > 0 && o.quantity > 0)
        .map(|o| o.cost / o.quantity as u64)
        .unwrap_or(0);
    let estimate = unit_cost * (demand - free - supply).max(rule.quantity as u64);
    if spent.saturating_add(estimate) > provider.monthly_spend_cap {
        return Ok(out_of_capacity(" (the purchase budget is used up)"));
    }
    Ok(IpSale::WaitForIp)
}

pub async fn sells_without_stock(db: &dyn LNVpsDb, region_id: u64, ip4_needed: u16) -> bool {
    matches!(
        sale_decision(db, region_id, ip4_needed).await,
        Ok(IpSale::WaitForIp)
    )
}

pub async fn vm_ip4_needed(db: &dyn LNVpsDb, vm: &lnvps_db::Vm) -> Result<u16> {
    if let Some(t) = vm.template_id {
        Ok(db.get_vm_template(t).await?.ip4_count)
    } else if let Some(t) = vm.custom_template_id {
        Ok(db.get_custom_vm_template(t).await?.ip4_count)
    } else {
        Ok(1)
    }
}
