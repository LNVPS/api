use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminVmIpAssignmentInfo, CreateVmIpAssignmentRequest, JobResponse, UpdateVmIpAssignmentRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, NetworkProvisioner, WorkJob,
};
use lnvps_db::{AdminAction, AdminResource, VmExtraAllowedIp};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/vm_ip_assignments",
            get(admin_list_vm_ip_assignments).post(admin_create_vm_ip_assignment),
        )
        .route(
            "/api/admin/v1/vm_ip_assignments/{id}",
            get(admin_get_vm_ip_assignment)
                .patch(admin_update_vm_ip_assignment)
                .delete(admin_delete_vm_ip_assignment),
        )
        .route(
            "/api/admin/v1/vms/{id}/extra_allowed_ips",
            get(admin_list_vm_extra_allowed_ips).post(admin_add_vm_extra_allowed_ip),
        )
        .route(
            "/api/admin/v1/vms/{id}/extra_allowed_ips/{entry_id}",
            delete(admin_remove_vm_extra_allowed_ip),
        )
}

#[derive(Serialize)]
struct AdminVmExtraAllowedIp {
    id: u64,
    vm_id: u64,
    ip: String,
    comment: String,
    created: DateTime<Utc>,
}

impl From<VmExtraAllowedIp> for AdminVmExtraAllowedIp {
    fn from(e: VmExtraAllowedIp) -> Self {
        Self {
            id: e.id,
            vm_id: e.vm_id,
            ip: e.ip,
            comment: e.comment,
            created: e.created,
        }
    }
}

#[derive(Deserialize)]
struct AddVmExtraAllowedIpRequest {
    ip: String,
    comment: String,
}

const EXTRA_IP_COMMENT_MAX: usize = 200;

fn parse_single_address(input: &str) -> Result<IpAddr, ApiError> {
    let input = input.trim();
    let (addr, prefix) = match input.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (input, None),
    };
    let addr: IpAddr = addr
        .parse()
        .map_err(|_| ApiError::bad_request("ip must be a literal IPv4 or IPv6 address"))?;
    let full = if addr.is_ipv4() { "32" } else { "128" };
    if prefix.is_some_and(|p| p != full) {
        return Err(ApiError::bad_request(format!(
            "ip must be a single address, a prefix other than /{full} is not allowed"
        )));
    }
    Ok(addr)
}

fn validate_comment(comment: &str) -> Result<String, ApiError> {
    let comment = comment.trim();
    if comment.is_empty() {
        return Err(ApiError::bad_request("comment is required"));
    }
    if comment.chars().count() > EXTRA_IP_COMMENT_MAX {
        return Err(ApiError::bad_request(format!(
            "comment must be at most {EXTRA_IP_COMMENT_MAX} characters"
        )));
    }
    if comment.chars().any(char::is_control) {
        return Err(ApiError::bad_request("comment must be a single line"));
    }
    Ok(comment.to_string())
}

async fn admin_list_vm_extra_allowed_ips(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<AdminVmExtraAllowedIp>> {
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::View)?;
    this.db.get_vm(id).await?;
    let rows = this.db.list_vm_extra_allowed_ips(id).await?;
    ApiData::ok(rows.into_iter().map(Into::into).collect())
}

async fn admin_add_vm_extra_allowed_ip(
    auth: AdminAuth,
    client: lnvps_api_common::ClientInfo,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AddVmExtraAllowedIpRequest>,
) -> ApiResult<AdminVmExtraAllowedIp> {
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;
    let addr = parse_single_address(&req.ip)?;
    let comment = validate_comment(&req.comment)?;
    let vm = this.db.get_vm(id).await?;
    if vm.deleted {
        return Err(ApiError::conflict(
            "Cannot add an allowed IP to a deleted VM",
        ));
    }
    let ip = addr.to_string();
    match this.db.get_vm_ip_assignment_by_ip(&ip).await {
        Ok(owner) => {
            let owner_vm = this.db.get_vm(owner.vm_id).await?;
            if owner_vm.user_id != vm.user_id {
                return Err(ApiError::conflict(format!(
                    "{ip} is assigned to VM {} of another user",
                    owner.vm_id
                )));
            }
        }
        Err(e) if e.is_row_not_found() => {}
        Err(e) => return Err(e.into()),
    }
    if this
        .db
        .list_vm_extra_allowed_ips(id)
        .await?
        .iter()
        .any(|e| e.ip == ip)
    {
        return Err(ApiError::conflict(format!(
            "{ip} is already allowed on VM {id}"
        )));
    }

    lnvps_api_common::record_audit(
        this.db.as_ref(),
        lnvps_api_common::with_client(
            lnvps_db::NewAuditEntry::new("admin", Some(auth.user_id), "admin.vm.extra_ip.add")
                .auth("nip98", None)
                .target("vm", id)
                .change(None, Some(format!("{ip} ({comment})"))),
            &client,
        ),
    )
    .await?;

    let entry_id = this
        .db
        .insert_vm_extra_allowed_ip(&VmExtraAllowedIp {
            vm_id: id,
            ip: ip.clone(),
            comment: comment.clone(),
            ..Default::default()
        })
        .await?;
    queue_firewall(&this, id).await;
    let saved = this
        .db
        .list_vm_extra_allowed_ips(id)
        .await?
        .into_iter()
        .find(|e| e.id == entry_id)
        .ok_or_else(|| ApiError::internal("extra allowed IP vanished after insert"))?;
    ApiData::ok(saved.into())
}

async fn admin_remove_vm_extra_allowed_ip(
    auth: AdminAuth,
    client: lnvps_api_common::ClientInfo,
    State(this): State<RouterState>,
    Path((id, entry_id)): Path<(u64, u64)>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;
    let entry = this
        .db
        .list_vm_extra_allowed_ips(id)
        .await?
        .into_iter()
        .find(|e| e.id == entry_id)
        .ok_or_else(|| ApiError::not_found("Extra allowed IP not found"))?;

    lnvps_api_common::record_audit(
        this.db.as_ref(),
        lnvps_api_common::with_client(
            lnvps_db::NewAuditEntry::new("admin", Some(auth.user_id), "admin.vm.extra_ip.remove")
                .auth("nip98", None)
                .target("vm", id)
                .change(Some(format!("{} ({})", entry.ip, entry.comment)), None),
            &client,
        ),
    )
    .await?;

    this.db.delete_vm_extra_allowed_ip(id, entry_id).await?;
    queue_firewall(&this, id).await;
    ApiData::ok(())
}

async fn queue_firewall(this: &RouterState, vm_id: u64) {
    if let Err(e) = this
        .work_commander
        .send(WorkJob::ApplyVmFirewall { vm_id })
        .await
    {
        log::warn!("Failed to queue firewall update for VM {vm_id}: {e}");
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VmIpAssignmentQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    vm_id: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    ip_range_id: Option<u64>,
    ip: Option<String>,
    include_deleted: Option<bool>,
}

/// List all VM IP assignments with pagination and optional filtering
async fn admin_list_vm_ip_assignments(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<VmIpAssignmentQuery>,
) -> ApiPaginatedResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = params.offset.unwrap_or(0);

    let (db_assignments, total) = this
        .db
        .admin_list_vm_ip_assignments(
            limit,
            offset,
            params.vm_id,
            params.ip_range_id,
            params.ip.as_deref(),
            params.include_deleted,
        )
        .await?;

    // Convert to API format with enriched data
    let mut assignments = Vec::new();
    for assignment in db_assignments {
        let admin_assignment =
            AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(&this.db, &assignment)
                .await?;
        assignments.push(admin_assignment);
    }

    ApiPaginatedData::ok(assignments, total, limit, offset)
}

/// Get a specific VM IP assignment by ID
async fn admin_get_vm_ip_assignment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::View)?;

    let assignment = this.db.admin_get_vm_ip_assignment(id).await?;
    let admin_assignment =
        AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(&this.db, &assignment).await?;

    ApiData::ok(admin_assignment)
}

/// Create a new VM IP assignment
async fn admin_create_vm_ip_assignment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateVmIpAssignmentRequest>,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Validate VM exists
    let vm = this.db.get_vm(req.vm_id).await?;
    if vm.deleted {
        return Err(ApiError::conflict("Cannot assign IP to a deleted VM"));
    }

    // Check subscription state (use shortcut function)
    let sub = this
        .db
        .get_subscription_by_line_item_id(vm.subscription_line_item_id)
        .await?;

    if !sub.is_setup {
        return Err(ApiError::conflict("Cannot assign IP to a new VM"));
    }

    if sub.expires.map(|e| e < Utc::now()).unwrap_or(true) {
        return Err(ApiError::conflict("Cannot assign IP to an expired VM"));
    }

    // Validate IP range exists and is enabled
    let ip_range = this.db.admin_get_ip_range(req.ip_range_id).await?;
    if !ip_range.enabled {
        return Err(ApiError::conflict(
            "Cannot assign IP from a disabled IP range",
        ));
    }

    // If IP is provided, validate it's within the range
    let assigned_ip = if let Some(ip) = &req.ip {
        // Validate IP format
        if ip.trim().parse::<IpAddr>().is_err() {
            return ApiData::err("Invalid IP address format");
        }

        // Parse the CIDR to validate the IP is within the range
        let cidr = ip_range
            .cidr
            .parse::<ipnetwork::IpNetwork>()
            .map_err(|_| "Invalid CIDR format in IP range")?;
        let provided_ip = ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "Invalid IP address format")?;

        if !cidr.contains(provided_ip) {
            return ApiData::err("IP address is not within the specified IP range");
        }

        ip.trim().to_string()
    } else {
        // Auto-assign IP from the range using NetworkProvisioner
        let network_provisioner = NetworkProvisioner::new(this.db.clone());
        match network_provisioner.pick_ip_from_range(&ip_range).await {
            Ok(available_ip) => available_ip.ip.ip().to_string(),
            Err(e) => {
                return ApiData::err(&format!("Failed to auto-assign IP from range: {}", e));
            }
        }
    };

    // Send AssignVmIp job to handle the assignment using the provisioner
    // This will create the IP assignment and handle all additional setup
    if let Err(e) = this
        .work_commander
        .send(WorkJob::AssignVmIp {
            vm_id: req.vm_id,
            ip_range_id: req.ip_range_id,
            ip: Some(assigned_ip.clone()),
            admin_user_id: Some(auth.user_id),
        })
        .await
    {
        log::error!(
            "Failed to queue IP assignment job for VM {}: {}",
            req.vm_id,
            e
        );
        return ApiData::err("Failed to queue IP assignment job");
    }

    // Return a success response indicating the job has been queued
    ApiData::ok(AdminVmIpAssignmentInfo {
        id: 0, // Will be assigned by worker
        vm_id: req.vm_id,
        ip_range_id: req.ip_range_id,
        region_id: 0, // Will be filled by worker
        user_id: 0,   // Will be filled by worker
        ip: assigned_ip,
        deleted: false,
        arp_ref: None,
        dns_forward: None,
        dns_forward_ref: None,
        dns_reverse: None,
        dns_reverse_ref: None,
        ip_range_cidr: None,
        region_name: None,
    })
}

/// Update VM IP assignment information
async fn admin_update_vm_ip_assignment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateVmIpAssignmentRequest>,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    let mut assignment = this.db.admin_get_vm_ip_assignment(id).await?;

    // Update IP if provided
    if let Some(ip) = &req.ip {
        if ip.trim().is_empty() {
            return ApiData::err("IP cannot be empty");
        }
        // Validate IP format
        if ip.trim().parse::<IpAddr>().is_err() {
            return ApiData::err("Invalid IP address format");
        }

        // Validate IP is within the range
        let ip_range = this.db.admin_get_ip_range(assignment.ip_range_id).await?;
        let cidr = ip_range
            .cidr
            .parse::<ipnetwork::IpNetwork>()
            .map_err(|_| "Invalid CIDR format in IP range")?;
        let provided_ip = ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "Invalid IP address format")?;

        if !cidr.contains(provided_ip) {
            return ApiData::err("IP address is not within the IP range");
        }

        assignment.ip = ip.trim().to_string();
    }

    // Update ARP ref if provided
    if let Some(arp_ref) = &req.arp_ref {
        assignment.arp_ref = arp_ref.clone();
    }

    // Update DNS forward if provided
    if let Some(dns_forward) = &req.dns_forward {
        assignment.dns_forward = dns_forward.clone();
    }

    // Update DNS reverse if provided
    if let Some(dns_reverse) = &req.dns_reverse {
        assignment.dns_reverse = dns_reverse.clone();
    }

    // Update assignment in database
    this.db.admin_update_vm_ip_assignment(&assignment).await?;

    // Return updated assignment
    let admin_assignment =
        AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(&this.db, &assignment).await?;

    // Send ConfigureVm job to update VM network configuration
    if let Err(e) = this
        .work_commander
        .send(WorkJob::UpdateVmIp {
            assignment_id: assignment.id,
            admin_user_id: Some(auth.user_id),
        })
        .await
    {
        // Log error but don't fail the API call
        log::warn!(
            "Failed to queue update vm ip job for VM {} after IP assignment update: {}",
            assignment.vm_id,
            e
        );
    }
    ApiData::ok(admin_assignment)
}

/// Delete a VM IP assignment (soft delete)
async fn admin_delete_vm_ip_assignment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<JobResponse> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Verify assignment exists
    let _assignment = this.db.admin_get_vm_ip_assignment(id).await?;

    // Send UnassignVmIp job to handle the unassignment using the provisioner
    // This will handle all cleanup (ARP, DNS, access policies) and then delete the assignment
    match this
        .work_commander
        .send(WorkJob::UnassignVmIp {
            assignment_id: id,
            admin_user_id: Some(auth.user_id),
        })
        .await
    {
        Ok(stream_id) => {
            log::info!("IP unassignment job queued with stream ID: {}", stream_id);
            ApiData::ok(JobResponse { job_id: stream_id })
        }
        Err(e) => {
            log::error!(
                "Failed to queue IP unassignment job for assignment {}: {}",
                id,
                e
            );
            ApiData::err("Failed to queue IP unassignment job")
        }
    }
}

#[cfg(test)]
mod extra_allowed_ip_tests {
    use super::*;
    use crate::admin::test_support::{Fixture, admin, fixture};
    use lnvps_api_common::{ClientInfo, MockDb};
    use lnvps_db::{LNVpsDbBase, VmIpAssignment};

    const VIP4: &str = "185.18.221.135";
    const VIP6: &str = "2a13:2c0::4dbc:733d:4d68:2e08";

    fn editor() -> AdminAuth {
        admin(
            7,
            &[
                (AdminResource::VirtualMachines, AdminAction::View),
                (AdminResource::VirtualMachines, AdminAction::Update),
            ],
        )
    }

    fn body(ip: &str) -> Json<AddVmExtraAllowedIpRequest> {
        Json(AddVmExtraAllowedIpRequest {
            ip: ip.to_string(),
            comment: "k8s ingress VIP".to_string(),
        })
    }

    async fn add(f: &Fixture, vm_id: u64, ip: &str) -> ApiResult<AdminVmExtraAllowedIp> {
        admin_add_vm_extra_allowed_ip(
            editor(),
            ClientInfo::default(),
            State(f.state.clone()),
            Path(vm_id),
            body(ip),
        )
        .await
    }

    async fn vm_of(f: &Fixture, user_id: u64) -> u64 {
        let mut vm = MockDb::mock_vm();
        vm.user_id = user_id;
        vm.ssh_key_id = None;
        f.mock.insert_vm(&vm).await.unwrap()
    }

    async fn assign(f: &Fixture, vm_id: u64, ip: &str) {
        f.mock
            .insert_vm_ip_assignment(&VmIpAssignment {
                vm_id,
                ip_range_id: 1,
                ip: ip.to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    #[test]
    fn only_a_single_address_is_accepted() {
        assert_eq!(parse_single_address(VIP4).unwrap().to_string(), VIP4);
        assert_eq!(
            parse_single_address(" 185.18.221.135/32 ")
                .unwrap()
                .to_string(),
            VIP4
        );
        assert_eq!(
            parse_single_address("2a13:02c0:0:0:4dbc:733d:4d68:2e08/128")
                .unwrap()
                .to_string(),
            VIP6
        );
        for bad in [
            "185.18.221.0/24",
            "185.18.221.135/31",
            "2a13:2c0::/64",
            "2a13:2c0::1/32",
            "185.18.221.135/128",
            "k8s.example.org",
            "",
            "185.18.221.135/",
        ] {
            assert!(parse_single_address(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_comment_is_one_short_line() {
        assert_eq!(
            validate_comment(" k8s ingress VIP ").unwrap(),
            "k8s ingress VIP"
        );
        assert!(validate_comment("  ").is_err());
        assert!(validate_comment("two\nlines").is_err());
        assert!(validate_comment(&"x".repeat(EXTRA_IP_COMMENT_MAX + 1)).is_err());
    }

    #[tokio::test]
    async fn an_address_of_another_users_vm_is_refused() {
        let f = fixture().await;
        let other_user = f.mock.upsert_user(&[4u8; 32]).await.unwrap();
        let other_vm = vm_of(&f, other_user).await;
        assign(&f, other_vm, VIP4).await;

        let err = add(&f, f.vm_id, VIP4).await.err().unwrap();
        assert_eq!(err.code, axum::http::StatusCode::CONFLICT);
        assert!(
            f.mock
                .list_vm_extra_allowed_ips(f.vm_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(f.audit_actions().await.is_empty());
        assert_eq!(f.queued_jobs().await, 0);
    }

    #[tokio::test]
    async fn an_address_of_the_same_users_other_vm_is_allowed() {
        let f = fixture().await;
        let k8s1 = vm_of(&f, f.owner_id).await;
        assign(&f, k8s1, VIP4).await;
        add(&f, f.vm_id, VIP4).await.unwrap();
        assert_eq!(
            f.mock
                .list_vm_extra_allowed_ips(f.vm_id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn add_list_remove_round_trip_is_audited_and_reapplies_the_firewall() {
        let f = fixture().await;
        let added = add(&f, f.vm_id, "2a13:02c0::4dbc:733d:4d68:2e08")
            .await
            .unwrap()
            .0
            .data;
        assert_eq!(added.ip, VIP6);
        assert_eq!(added.comment, "k8s ingress VIP");
        assert_eq!(f.queued_jobs().await, 1);

        let dup = add(&f, f.vm_id, VIP6).await.err().unwrap();
        assert_eq!(dup.code, axum::http::StatusCode::CONFLICT);

        let listed =
            admin_list_vm_extra_allowed_ips(editor(), State(f.state.clone()), Path(f.vm_id))
                .await
                .unwrap()
                .0
                .data;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, added.id);

        let wrong_vm = admin_remove_vm_extra_allowed_ip(
            editor(),
            ClientInfo::default(),
            State(f.state.clone()),
            Path((f.vm_id + 1, added.id)),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(wrong_vm.code, axum::http::StatusCode::NOT_FOUND);

        admin_remove_vm_extra_allowed_ip(
            editor(),
            ClientInfo::default(),
            State(f.state.clone()),
            Path((f.vm_id, added.id)),
        )
        .await
        .unwrap();
        assert!(
            f.mock
                .list_vm_extra_allowed_ips(f.vm_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(f.queued_jobs().await, 1);
        assert_eq!(
            f.audit_actions().await,
            vec!["admin.vm.extra_ip.add", "admin.vm.extra_ip.remove"]
        );
        let log = f.mock.audit_log.lock().await;
        assert_eq!(log[0].actor_id, Some(7));
        assert_eq!(
            log[0].target_id.as_deref(),
            Some(f.vm_id.to_string().as_str())
        );
        assert!(log[0].after_summary.as_deref().unwrap().contains(VIP6));
    }

    #[tokio::test]
    async fn a_failed_audit_write_blocks_the_change() {
        let f = fixture().await;
        f.break_audit_log();
        assert!(add(&f, f.vm_id, VIP4).await.is_err());
        assert!(
            f.mock
                .list_vm_extra_allowed_ips(f.vm_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn viewing_needs_vm_view_and_editing_needs_vm_update() {
        let f = fixture().await;
        let none = admin(9, &[]);
        assert!(
            admin_list_vm_extra_allowed_ips(none, State(f.state.clone()), Path(f.vm_id))
                .await
                .is_err()
        );
        let viewer = admin(9, &[(AdminResource::VirtualMachines, AdminAction::View)]);
        assert!(
            admin_add_vm_extra_allowed_ip(
                viewer,
                ClientInfo::default(),
                State(f.state.clone()),
                Path(f.vm_id),
                body(VIP4),
            )
            .await
            .is_err()
        );
    }
}
