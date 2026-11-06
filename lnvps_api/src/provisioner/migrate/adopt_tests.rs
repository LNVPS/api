use super::*;
use crate::host::dummy_host::{DummyFault, DummyVmHost};
use crate::settings::mock_settings;
use lnvps_api_common::{GB, MockDb, MockDnsServer};
use lnvps_db::{
    CpuArch, IpRange, IpRangeAllocationMode, LNVpsDbBase, Region, VmHistoryActionType, VmHostDisk,
    VmHostKind,
};

const SRC: u64 = 21;
const DST: u64 = 22;
const DST_DISK: u64 = 32;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct World {
    db: Arc<MockDb>,
    provisioner: VmProvisioner,
    vm_id: u64,
    disk: Vec<u8>,
}

fn host(id: u64, kind: VmHostKind, region: u64) -> VmHost {
    VmHost {
        id,
        kind,
        region_id: region,
        name: format!("host-{id}"),
        ip: "https://localhost".to_string(),
        cpu: 64,
        cpu_arch: CpuArch::X86_64,
        memory: 512 * GB,
        enabled: true,
        load_cpu: 1.0,
        load_memory: 1.0,
        load_disk: 1.0,
        ..Default::default()
    }
}

async fn world(target_region: u64) -> World {
    let db = Arc::new(MockDb::default());
    DummyVmHost::clear_disks().await;
    MockDnsServer::reset().await;
    db.regions.lock().await.insert(
        2,
        Region {
            id: 2,
            name: "Far".to_string(),
            enabled: true,
            company_id: 1,
            country_code: Some("DE".to_string()),
        },
    );
    db.ip_range.lock().await.insert(
        3,
        IpRange {
            id: 3,
            cidr: "10.9.0.0/24".to_string(),
            gateway: "10.9.0.1/24".to_string(),
            enabled: true,
            region_id: 2,
            allocation_mode: IpRangeAllocationMode::Sequential,
            forward_dns_server_id: Some(1),
            forward_zone_id: Some("mock-forward-zone-id".to_string()),
            ..Default::default()
        },
    );
    {
        let mut hosts = db.hosts.lock().await;
        hosts.insert(SRC, host(SRC, VmHostKind::MarketplaceNode, 1));
        hosts.insert(DST, host(DST, VmHostKind::Proxmox, target_region));
    }
    {
        let mut disks = db.host_disks.lock().await;
        for (id, host_id, name) in [(31, SRC, "default"), (DST_DISK, DST, "local-zfs")] {
            disks.insert(
                id,
                VmHostDisk {
                    id,
                    host_id,
                    name: name.to_string(),
                    size: 10_000 * GB,
                    enabled: true,
                    ..Default::default()
                },
            );
        }
    }

    let pubkey: [u8; 32] = rand::random();
    let user_id = db.upsert_user(&pubkey).await.unwrap();
    let ssh_key_id = db
        .insert_user_ssh_key(&lnvps_db::UserSshKey {
            name: "k".to_string(),
            user_id,
            key_data: "ssh-ed25519 AAAA".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let vm_id = db
        .insert_vm(&Vm {
            host_id: SRC,
            user_id,
            image_id: 1,
            template_id: Some(1),
            ssh_key_id: Some(ssh_key_id),
            disk_id: 31,
            mac_address: "52:54:00:12:34:56".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    db.insert_vm_ip_assignment(&VmIpAssignment {
        vm_id,
        ip_range_id: 1,
        ip: "10.0.0.50".to_string(),
        ..Default::default()
    })
    .await
    .unwrap();

    let disk: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 256) as u8).collect();
    DummyVmHost::set_disk(SRC, vm_id, disk.clone()).await;
    let src = DummyVmHost::new().with_host_id(SRC);
    src.create_vm(&FullVmInfo::load(vm_id, db.clone()).await.unwrap())
        .await
        .unwrap();
    src.start_vm(&db.get_vm(vm_id).await.unwrap())
        .await
        .unwrap();

    let clients: Arc<std::sync::Mutex<std::collections::HashMap<u64, DummyVmHost>>> = Arc::new(
        std::sync::Mutex::new(std::collections::HashMap::from([(SRC, src)])),
    );
    let provisioner = VmProvisioner::new(mock_settings(), db.clone()).with_host_clients(
        move |h: &VmHost| -> Arc<dyn VmHostClient> {
            let mut c = clients.lock().unwrap();
            Arc::new(
                c.entry(h.id)
                    .or_insert_with(|| DummyVmHost::new().with_host_id(h.id))
                    .clone(),
            )
        },
    );
    World {
        db,
        provisioner,
        vm_id,
        disk,
    }
}

async fn state_on(w: &World, host_id: u64) -> Option<VmRunningStates> {
    let h = w.db.get_host(host_id).await.unwrap();
    let vm = w.db.get_vm(w.vm_id).await.unwrap();
    w.provisioner
        .host_client(&h)
        .await
        .unwrap()
        .get_vm_state(&vm)
        .await
        .ok()
        .map(|s| s.state)
}

async fn phases(w: &World) -> Vec<String> {
    let mut h = w.db.list_vm_history(w.vm_id).await.unwrap();
    h.sort_by_key(|h| h.id);
    h.iter()
        .filter(|h| matches!(h.action_type, VmHistoryActionType::MigrationProgress))
        .map(|h| {
            let m: serde_json::Value =
                serde_json::from_slice(h.metadata.as_ref().unwrap()).unwrap();
            m["phase"].as_str().unwrap().to_string()
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn marketplace_vm_is_copied_byte_for_byte_and_adopted_on_proxmox() {
    let _s = SERIAL.lock().await;
    let w = world(1).await;
    let out = w
        .provisioner
        .migrate_vm_with(w.vm_id, DST, false, &MigrationOptions::default(), Some(3))
        .await
        .expect("migration");

    assert_eq!(out.method, MigrationMethod::CopyAndAdopt);
    assert_eq!(out.needs_attention, None);
    assert!(out.source_retained);
    let vm = w.db.get_vm(w.vm_id).await.unwrap();
    assert_eq!((vm.host_id, vm.disk_id), (DST, DST_DISK));
    assert_eq!(vm.mac_address, "52:54:00:12:34:56");
    assert_eq!(DummyVmHost::disk(DST, w.vm_id).await, Some(w.disk.clone()));
    assert_eq!(state_on(&w, DST).await, Some(VmRunningStates::Running));
    assert_eq!(state_on(&w, SRC).await, Some(VmRunningStates::Stopped));
    assert!(DummyVmHost::is_retired(SRC, w.vm_id).await);

    let m = &w.db.list_vm_migrations(w.vm_id).await.unwrap()[0];
    assert_eq!(m.state, VmMigrationState::Completed);
    assert!(m.flipped && m.source_retained && !m.needs_attention);
    assert_eq!(m.bytes_copied, w.disk.len() as u64);
    assert_eq!(
        phases(&w).await.first().map(String::as_str),
        Some("started")
    );
    assert!(phases(&w).await.contains(&"verified".to_string()));
    assert!(
        w.db.list_vm_history(w.vm_id)
            .await
            .unwrap()
            .iter()
            .any(|h| matches!(h.action_type, VmHistoryActionType::Migrated))
    );
}

#[tokio::test(start_paused = true)]
async fn keep_source_false_deletes_the_source_copy_after_success() {
    let _s = SERIAL.lock().await;
    let w = world(1).await;
    let opts = MigrationOptions {
        keep_source: false,
        ..Default::default()
    };
    let out = w
        .provisioner
        .migrate_vm_with(w.vm_id, DST, false, &opts, None)
        .await
        .unwrap();
    assert!(!out.source_retained);
    assert_eq!(state_on(&w, SRC).await, None);
    assert!(DummyVmHost::disk(SRC, w.vm_id).await.is_none());
}

#[tokio::test(start_paused = true)]
async fn checksum_mismatch_rolls_back_and_restarts_the_source() {
    let _s = SERIAL.lock().await;
    let w = world(1).await;
    DummyVmHost::set_fault(DST, Some(DummyFault::CorruptImport)).await;
    let err = w
        .provisioner
        .migrate_vm_with(w.vm_id, DST, false, &MigrationOptions::default(), None)
        .await
        .expect_err("a corrupted copy must not be adopted");
    assert!(format!("{err:#}").contains("checksum mismatch"), "{err:#}");

    let vm = w.db.get_vm(w.vm_id).await.unwrap();
    assert_eq!((vm.host_id, vm.disk_id), (SRC, 31));
    assert_eq!(state_on(&w, SRC).await, Some(VmRunningStates::Running));
    assert_eq!(state_on(&w, DST).await, None, "half-made copy removed");
    assert!(DummyVmHost::disk(DST, w.vm_id).await.is_none());
    let m = &w.db.list_vm_migrations(w.vm_id).await.unwrap()[0];
    assert_eq!(m.state, VmMigrationState::RolledBack);
    assert!(!m.flipped);
    assert!(phases(&w).await.contains(&"rolled_back".to_string()));
    DummyVmHost::set_fault(DST, None).await;
}

#[tokio::test(start_paused = true)]
async fn import_failure_before_flip_leaves_the_vm_where_it_was() {
    let _s = SERIAL.lock().await;
    let w = world(1).await;
    DummyVmHost::set_fault(DST, Some(DummyFault::ImportFails)).await;
    assert!(
        w.provisioner
            .migrate_vm_with(w.vm_id, DST, false, &MigrationOptions::default(), None)
            .await
            .is_err()
    );
    assert_eq!(w.db.get_vm(w.vm_id).await.unwrap().host_id, SRC);
    assert_eq!(state_on(&w, SRC).await, Some(VmRunningStates::Running));
    assert!(
        w.db.get_active_vm_migration(w.vm_id)
            .await
            .unwrap()
            .is_none()
    );
    DummyVmHost::set_fault(DST, None).await;

    let out = w
        .provisioner
        .migrate_vm_with(w.vm_id, DST, false, &MigrationOptions::default(), None)
        .await
        .expect("a retry after a rolled-back attempt succeeds");
    assert_eq!(out.vm.host_id, DST);
}

#[tokio::test(start_paused = true)]
async fn failure_after_flip_stays_on_the_destination_and_is_flagged() {
    let _s = SERIAL.lock().await;
    let w = world(1).await;
    DummyVmHost::set_fault(DST, Some(DummyFault::StartFails)).await;
    let out = w
        .provisioner
        .migrate_vm_with(
            w.vm_id,
            DST,
            false,
            &MigrationOptions {
                keep_source: false,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("past the switch-over a failure is a follow-up, not a rollback");
    assert!(
        out.needs_attention
            .as_deref()
            .unwrap()
            .contains("start on destination")
    );
    assert_eq!(out.vm.host_id, DST);
    assert!(
        out.source_retained,
        "the source copy is not deleted while something is wrong"
    );
    assert!(DummyVmHost::disk(SRC, w.vm_id).await.is_some());
    let m = &w.db.list_open_vm_migrations().await.unwrap()[0];
    assert!(m.needs_attention && m.flipped);
    DummyVmHost::set_fault(DST, None).await;
}

#[tokio::test(start_paused = true)]
async fn retry_removes_a_stale_destination_copy_from_an_interrupted_attempt() {
    let _s = SERIAL.lock().await;
    let w = world(1).await;
    w.db.insert_vm_migration(&VmMigration {
        vm_id: w.vm_id,
        source_host_id: SRC,
        target_host_id: DST,
        target_disk_id: DST_DISK,
        state: VmMigrationState::Failed,
        ..Default::default()
    })
    .await
    .unwrap();
    DummyVmHost::set_disk(DST, w.vm_id, vec![1, 2, 3]).await;
    let dst = w
        .provisioner
        .host_client(&w.db.get_host(DST).await.unwrap())
        .await
        .unwrap();
    dst.create_vm(&FullVmInfo::load(w.vm_id, w.db.clone()).await.unwrap())
        .await
        .unwrap();

    w.provisioner
        .migrate_vm_with(w.vm_id, DST, false, &MigrationOptions::default(), None)
        .await
        .expect("stale copy is cleaned up");
    assert_eq!(DummyVmHost::disk(DST, w.vm_id).await, Some(w.disk.clone()));
}

#[tokio::test(start_paused = true)]
async fn an_unexplained_vm_on_the_destination_is_never_overwritten() {
    let _s = SERIAL.lock().await;
    let w = world(1).await;
    let dst = w
        .provisioner
        .host_client(&w.db.get_host(DST).await.unwrap())
        .await
        .unwrap();
    dst.create_vm(&FullVmInfo::load(w.vm_id, w.db.clone()).await.unwrap())
        .await
        .unwrap();
    let err = w
        .provisioner
        .migrate_vm_with(w.vm_id, DST, false, &MigrationOptions::default(), None)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("refusing to overwrite"),
        "{err:#}"
    );
    assert_eq!(state_on(&w, DST).await, Some(VmRunningStates::Stopped));
}

#[tokio::test(start_paused = true)]
async fn a_vm_already_migrating_is_refused() {
    let _s = SERIAL.lock().await;
    let w = world(1).await;
    w.db.insert_vm_migration(&VmMigration {
        vm_id: w.vm_id,
        phase: "copying".to_string(),
        ..Default::default()
    })
    .await
    .unwrap();
    let err = w
        .provisioner
        .migrate_vm_with(w.vm_id, DST, false, &MigrationOptions::default(), None)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("already being migrated"),
        "{err:#}"
    );
    assert_eq!(state_on(&w, SRC).await, Some(VmRunningStates::Running));
}

#[tokio::test(start_paused = true)]
async fn cross_region_keep_is_refused_without_touching_anything() {
    let _s = SERIAL.lock().await;
    let w = world(2).await;
    let err = w
        .provisioner
        .migrate_vm_with(w.vm_id, DST, false, &MigrationOptions::default(), None)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("ip_policy=reassign"), "{err:#}");
    assert_eq!(state_on(&w, SRC).await, Some(VmRunningStates::Running));
    assert!(w.db.list_vm_migrations(w.vm_id).await.unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn reassign_allocates_destination_addresses_and_moves_dns() {
    let _s = SERIAL.lock().await;
    let w = world(2).await;
    let mut old =
        w.db.list_vm_ip_assignments(w.vm_id)
            .await
            .unwrap()
            .remove(0);
    w.provisioner.refresh_ip_policy(&mut old).await.unwrap();
    assert!(old.dns_forward_ref.is_some());
    let zone = || async {
        MockDnsServer::new()
            .zones
            .lock()
            .await
            .get("mock-forward-zone-id")
            .map(|z| z.values().map(|e| e.value.clone()).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    assert_eq!(zone().await, vec!["10.0.0.50".to_string()]);

    let out = w
        .provisioner
        .migrate_vm_with(
            w.vm_id,
            DST,
            false,
            &MigrationOptions {
                ip_policy: IpPolicy::Reassign,
                ..Default::default()
            },
            Some(3),
        )
        .await
        .expect("reassign");
    assert_eq!(out.needs_attention, None);
    assert_eq!(out.reassigned.len(), 1);
    assert_eq!(out.reassigned[0].old_ip, "10.0.0.50");
    let new_ip = out.reassigned[0].new_ip.clone().unwrap();
    assert!(new_ip.starts_with("10.9.0."), "{new_ip}");

    let live: Vec<_> =
        w.db.list_vm_ip_assignments(w.vm_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|i| !i.deleted)
            .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].ip, new_ip);
    assert_eq!(live[0].ip_range_id, 3);
    assert!(live[0].dns_forward_ref.is_some());
    assert_eq!(zone().await, vec![new_ip.clone()]);

    let m = &w.db.list_vm_migrations(w.vm_id).await.unwrap()[0];
    assert!(m.old_ips.as_deref().unwrap().contains("10.0.0.50"));
    let migrated =
        w.db.list_vm_history(w.vm_id)
            .await
            .unwrap()
            .into_iter()
            .find(|h| matches!(h.action_type, VmHistoryActionType::Migrated))
            .unwrap();
    let meta: serde_json::Value = serde_json::from_slice(&migrated.metadata.unwrap()).unwrap();
    assert_eq!(meta["reassigned"][0]["old_ip"], "10.0.0.50");
    assert_eq!(meta["ip_policy"], "reassign");
}

#[tokio::test(start_paused = true)]
async fn reassign_failure_before_flip_frees_the_new_addresses() {
    let _s = SERIAL.lock().await;
    let w = world(2).await;
    DummyVmHost::set_fault(DST, Some(DummyFault::ImportFails)).await;
    assert!(
        w.provisioner
            .migrate_vm_with(
                w.vm_id,
                DST,
                false,
                &MigrationOptions {
                    ip_policy: IpPolicy::Reassign,
                    ..Default::default()
                },
                None,
            )
            .await
            .is_err()
    );
    let ips = w.db.list_vm_ip_assignments(w.vm_id).await.unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0].ip, "10.0.0.50");
    DummyVmHost::set_fault(DST, None).await;
}

#[tokio::test(start_paused = true)]
async fn dry_run_plan_changes_nothing() {
    let _s = SERIAL.lock().await;
    let w = world(2).await;
    let before = w.db.get_vm(w.vm_id).await.unwrap();
    let plan = w
        .provisioner
        .plan_vm_migration(
            w.vm_id,
            DST,
            &MigrationOptions {
                ip_policy: IpPolicy::Reassign,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(plan.allowed(), "{:?}", plan.refusals);
    assert_eq!(plan.ip_changes[0].old_ip.as_deref(), Some("10.0.0.50"));
    assert!(plan.warnings.iter().any(|w| w.contains("marketplace node")));
    let after = w.db.get_vm(w.vm_id).await.unwrap();
    assert_eq!(
        (before.host_id, before.disk_id),
        (after.host_id, after.disk_id)
    );
    assert!(w.db.list_vm_migrations(w.vm_id).await.unwrap().is_empty());
    assert!(w.db.list_vm_history(w.vm_id).await.unwrap().is_empty());
    assert_eq!(state_on(&w, SRC).await, Some(VmRunningStates::Running));
    assert!(DummyVmHost::disk(DST, w.vm_id).await.is_none());
}
