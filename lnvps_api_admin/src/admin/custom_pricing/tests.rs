use super::*;
use lnvps_api_common::ApiIntervalType;
use crate::admin::model::Permission;
use lnvps_api_common::{ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache};
use serde_json::json;

fn state() -> RouterState {
    RouterState {
        node_control: None,
        db: Arc::new(MockDb::default()),
        work_commander: Arc::new(ChannelWorkCommander::new()),
        feedback: None,
        vm_state_cache: VmStateCache::new(),
        exchange: Arc::new(MockExchangeRate::default()),
        vat: VatClient::new(),
    }
}

fn auth() -> AdminAuth {
    AdminAuth {
        user_id: 1,
        pubkey: vec![1u8; 32],
        permissions: [AdminAction::Create, AdminAction::Update, AdminAction::View]
            .into_iter()
            .map(|action| Permission {
                resource: AdminResource::VmCustomPricing,
                action,
            })
            .collect(),
        nip98_auth: None,
    }
}

fn create_request(extra: serde_json::Value) -> CreateCustomPricingRequest {
    let mut body = json!({
        "name": "plan",
        "region_id": 1,
        "currency": "EUR",
        "cpu_cost": 100,
        "memory_cost": 50,
        "ip4_cost": 0,
        "ip6_cost": 0,
        "min_cpu": 1,
        "max_cpu": 4,
        "min_memory": 1,
        "max_memory": 2,
        "disk_pricing": []
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    serde_json::from_value(body).unwrap()
}

#[tokio::test]
async fn create_defaults_bandwidth_range_to_the_plan_value() {
    let this = state();
    let out = admin_create_custom_pricing(
        auth(),
        State(this),
        Json(create_request(json!({
            "transfer_gb": 1000,
            "network_mbps": 500,
            "network_cost_per_gbps": 300
        }))),
    )
    .await
    .unwrap();
    let info = out.0.data;
    assert_eq!(info.transfer_gb, Some(1000));
    assert_eq!((info.min_transfer_gb, info.max_transfer_gb), (1000, 1000));
    assert_eq!(info.transfer_cost_per_tb, 0);
    assert_eq!((info.min_network_mbps, info.max_network_mbps), (500, 500));
    assert_eq!(info.network_cost_per_gbps, 300);
}

#[tokio::test]
async fn create_rejects_a_default_outside_the_range() {
    let res = admin_create_custom_pricing(
        auth(),
        State(state()),
        Json(create_request(json!({
            "network_mbps": 50,
            "min_network_mbps": 100,
            "max_network_mbps": 1000
        }))),
    )
    .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn update_and_copy_carry_bandwidth_pricing() {
    let this = state();
    let id = admin_create_custom_pricing(
        auth(),
        State(this.clone()),
        Json(create_request(json!({ "transfer_gb": 1000 }))),
    )
    .await
    .unwrap()
    .0
    .data
    .id;

    let patch: UpdateCustomPricingRequest = serde_json::from_value(json!({
        "min_transfer_gb": 500,
        "max_transfer_gb": 8000,
        "transfer_cost_per_tb": 120,
        "network_mbps": 1000,
        "min_network_mbps": 100,
        "max_network_mbps": 10000,
        "network_cost_per_gbps": 250
    }))
    .unwrap();
    let info = admin_update_custom_pricing(auth(), State(this.clone()), Path(id), Json(patch))
        .await
        .unwrap()
        .0
        .data;
    assert_eq!((info.min_transfer_gb, info.max_transfer_gb), (500, 8000));
    assert_eq!(info.transfer_cost_per_tb, 120);
    assert_eq!(info.network_mbps, Some(1000));
    assert_eq!((info.min_network_mbps, info.max_network_mbps), (100, 10000));
    assert_eq!(info.network_cost_per_gbps, 250);

    let inverted: UpdateCustomPricingRequest =
        serde_json::from_value(json!({ "min_transfer_gb": 9000 })).unwrap();
    assert!(
        admin_update_custom_pricing(auth(), State(this.clone()), Path(id), Json(inverted))
            .await
            .is_err()
    );

    let copy: CopyCustomPricingRequest = serde_json::from_value(json!({ "name": "copy" })).unwrap();
    let copied = admin_copy_custom_pricing(auth(), State(this), Path(id), Json(copy))
        .await
        .unwrap()
        .0
        .data;
    assert_eq!(copied.max_transfer_gb, 8000);
    assert_eq!(copied.transfer_cost_per_tb, 120);
    assert_eq!(copied.max_network_mbps, 10000);
    assert_eq!(copied.network_cost_per_gbps, 250);
}

#[tokio::test]
async fn interval_defaults_to_monthly_and_copy_can_override_it() {
    let this = state();
    let created = admin_create_custom_pricing(
        auth(),
        State(this.clone()),
        Json(create_request(json!({}))),
    )
    .await
    .unwrap()
    .0
    .data;
    assert_eq!(created.interval_amount, 1);
    assert_eq!(created.interval_type, ApiIntervalType::Month);

    // A plain copy keeps the source's interval.
    let copy: CopyCustomPricingRequest = serde_json::from_value(json!({ "name": "same" })).unwrap();
    let same = admin_copy_custom_pricing(auth(), State(this.clone()), Path(created.id), Json(copy))
        .await
        .unwrap()
        .0
        .data;
    assert_eq!(same.interval_type, ApiIntervalType::Month);

    // A copy can switch to hourly in one call.
    let copy: CopyCustomPricingRequest = serde_json::from_value(
        json!({ "name": "hourly", "interval_type": "hour", "interval_amount": 1 }),
    )
    .unwrap();
    let hourly = admin_copy_custom_pricing(auth(), State(this.clone()), Path(created.id), Json(copy))
        .await
        .unwrap()
        .0
        .data;
    assert_eq!(hourly.interval_type, ApiIntervalType::Hour);
    assert_eq!(hourly.cpu_cost, created.cpu_cost);

    // Update changes it; a zero amount is refused.
    let patch: UpdateCustomPricingRequest =
        serde_json::from_value(json!({ "interval_type": "day", "interval_amount": 2 })).unwrap();
    let updated = admin_update_custom_pricing(auth(), State(this.clone()), Path(created.id), Json(patch))
        .await
        .unwrap()
        .0
        .data;
    assert_eq!(updated.interval_type, ApiIntervalType::Day);
    assert_eq!(updated.interval_amount, 2);
    let zero: UpdateCustomPricingRequest =
        serde_json::from_value(json!({ "interval_amount": 0 })).unwrap();
    assert!(
        admin_update_custom_pricing(auth(), State(this), Path(created.id), Json(zero))
            .await
            .is_err()
    );
}
