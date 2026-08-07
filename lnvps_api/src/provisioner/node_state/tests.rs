//! What a node is told to build.
//!
//! These assertions are the wire contract. A node applies this document without
//! being able to ask a follow-up question, so anything ambiguous here becomes a
//! guest that boots wrong on somebody else's hardware.

use lnvps_api_common::MockDb;
use lnvps_db::{
    LNVpsDbBase, MarketplaceNode, MarketplaceNodeStatus, MarketplaceOperator, UserSshKey, Vm,
    VmHost, VmHostKind,
};

use super::*;

/// A node with a host, one VM, one address, and an SSH key — the smallest
/// arrangement that produces a document worth checking.
async fn node_with_a_vm(db: &Arc<MockDb>) -> Result<(MarketplaceNode, u64)> {
    let dbt: Arc<dyn LNVpsDb> = db.clone();
    let user_id = dbt.upsert_user(&[9u8; 32]).await?;
    let operator_id = dbt
        .insert_marketplace_operator(&MarketplaceOperator {
            user_id,
            enabled: true,
            ..Default::default()
        })
        .await?;
    let node_id = dbt
        .insert_marketplace_node(&MarketplaceNode {
            operator_id,
            name: "rack 1".to_string(),
            status: MarketplaceNodeStatus::Approved,
            ..Default::default()
        })
        .await?;
    let host_id = dbt
        .create_host(&VmHost {
            kind: VmHostKind::MarketplaceNode,
            region_id: 1,
            name: "node-host".to_string(),
            enabled: false,
            marketplace_node_id: Some(node_id),
            ..Default::default()
        })
        .await?;
    let ssh_key_id = dbt
        .insert_user_ssh_key(&UserSshKey {
            name: "k".to_string(),
            user_id,
            key_data: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@lnvps"
                .to_string()
                .into(),
            ..Default::default()
        })
        .await?;

    let vm_id = {
        let mut vms = db.vms.lock().await;
        let id = vms.keys().max().copied().unwrap_or(0) + 1;
        vms.insert(
            id,
            Vm {
                id,
                host_id,
                user_id,
                image_id: 1,
                template_id: Some(1),
                disk_id: 1,
                ssh_key_id: Some(ssh_key_id),
                mac_address: "52:54:00:11:22:33".to_string(),
                ..Default::default()
            },
        );
        id
    };
    dbt.insert_vm_ip_assignment(&lnvps_db::VmIpAssignment {
        vm_id,
        ip_range_id: 1,
        ip: "10.0.0.5".to_string(),
        ..Default::default()
    })
    .await?;

    Ok((dbt.get_marketplace_node(node_id).await?, vm_id))
}

/// The document describes a machine, not a database. Everything the node needs
/// to build a guest is here, and nothing about who is paying for it.
#[tokio::test]
async fn a_node_is_told_what_to_build() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let (node, vm_id) = node_with_a_vm(&db).await?;
    let dbt: Arc<dyn LNVpsDb> = db.clone();

    let state = node_state(&dbt, &node).await?;
    assert_eq!(state.vms.len(), 1);
    let vm = &state.vms[0];

    assert_eq!(vm.id, vm_id);
    assert!(vm.cpu > 0 && vm.memory > 0 && vm.disk_bytes > 0, "{vm:?}");
    assert_eq!(vm.mac, "52:54:00:11:22:33");
    // A host prefix, matching how the data plane states guest addresses — the
    // node holds them the same way on both sides.
    assert_eq!(vm.addresses, vec!["10.0.0.5/32".to_string()]);
    assert!(vm.running, "a VM nobody disabled is one to run");
    Ok(())
}

/// Cloud-init arrives rendered. LNVPS decides what a guest is configured with;
/// a node that rendered it would configure guests differently as soon as one
/// machine in the fleet ran an older daemon.
#[tokio::test]
async fn cloud_init_is_rendered_by_lnvps() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let (node, vm_id) = node_with_a_vm(&db).await?;
    let dbt: Arc<dyn LNVpsDb> = db.clone();

    let state = node_state(&dbt, &node).await?;
    let ci = &state.vms[0].cloud_init;

    assert!(
        ci.user_data.contains("ssh-ed25519"),
        "the key must be in it"
    );
    assert!(
        ci.meta_data.contains(&vm_id.to_string()),
        "{}",
        ci.meta_data
    );
    // Matched to the NIC by MAC, because the guest's name for the interface
    // depends on its distro and LNVPS cannot know it.
    assert!(
        ci.network_config.contains("52:54:00:11:22:33"),
        "{}",
        ci.network_config
    );
    assert!(
        ci.network_config.contains("10.0.0.5"),
        "{}",
        ci.network_config
    );
    Ok(())
}

/// The image is a URL and a checksum, because the node fetches it over its own
/// connection. Streaming images through LNVPS would make every provision wait
/// on our bandwidth for a file the node can get directly.
#[tokio::test]
async fn the_image_is_fetched_by_the_node() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let (node, _) = node_with_a_vm(&db).await?;
    let dbt: Arc<dyn LNVpsDb> = db.clone();

    let image = dbt.get_os_image(1).await?;
    let state = node_state(&dbt, &node).await?;
    let sent = &state.vms[0].image;

    assert_eq!(sent.url, image.url);
    assert_eq!(sent.sha2, image.sha2);
    // Cached under the name from the URL, so two VMs from one image share a
    // download and an operator can tell what the file in their pool is.
    assert!(!sent.filename.is_empty());
    assert!(!sent.filename.contains('/'), "{}", sent.filename);
    Ok(())
}

/// A deleted VM is absent, which is how the node is told to destroy it. There
/// is no delete message: the absence is the message, and it still works if
/// LNVPS was down when the deletion happened.
#[tokio::test]
async fn a_deleted_vm_is_simply_absent() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let (node, vm_id) = node_with_a_vm(&db).await?;
    let dbt: Arc<dyn LNVpsDb> = db.clone();

    {
        let mut vms = db.vms.lock().await;
        vms.get_mut(&vm_id).unwrap().deleted = true;
    }
    assert!(node_state(&dbt, &node).await?.vms.is_empty());
    Ok(())
}

/// A disabled VM stays in the document and is marked not-running. Removing it
/// would tell the node to destroy the customer's disk, which is a very
/// different thing from "stop billing this".
#[tokio::test]
async fn a_disabled_vm_is_kept_but_not_run() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let (node, vm_id) = node_with_a_vm(&db).await?;
    let dbt: Arc<dyn LNVpsDb> = db.clone();

    {
        let mut vms = db.vms.lock().await;
        vms.get_mut(&vm_id).unwrap().disabled = true;
    }
    let state = node_state(&dbt, &node).await?;
    assert_eq!(state.vms.len(), 1, "the disk must not be destroyed");
    assert!(!state.vms[0].running);
    Ok(())
}

/// A node with no tunnel is told it has no data plane rather than being sent
/// VMs it has nowhere to put.
#[tokio::test]
async fn a_node_with_no_tunnel_is_told_so() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let (node, _) = node_with_a_vm(&db).await?;
    let dbt: Arc<dyn LNVpsDb> = db.clone();

    let state = node_state(&dbt, &node).await?;
    assert!(state.dataplane.is_none());
    // ...and still told about its VMs, because the node's disks and domains
    // outlive its network: a tunnel that is being re-allocated must not look
    // like an instruction to destroy every customer on the machine.
    assert_eq!(state.vms.len(), 1);
    Ok(())
}

/// A node that has never been approved has no host, so there is nothing to run
/// and it is told exactly that.
#[tokio::test]
async fn an_unapproved_node_runs_nothing() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let dbt: Arc<dyn LNVpsDb> = db.clone();
    let user_id = dbt.upsert_user(&[3u8; 32]).await?;
    let operator_id = dbt
        .insert_marketplace_operator(&MarketplaceOperator {
            user_id,
            enabled: true,
            ..Default::default()
        })
        .await?;
    let node_id = dbt
        .insert_marketplace_node(&MarketplaceNode {
            operator_id,
            name: "unapproved".to_string(),
            ..Default::default()
        })
        .await?;
    let node = dbt.get_marketplace_node(node_id).await?;

    let state = node_state(&dbt, &node).await?;
    assert!(state.vms.is_empty());
    assert!(state.dataplane.is_none());
    Ok(())
}

/// The list is ordered, so two fetches of an unchanged machine produce the same
/// document. A node that reconciled against a reordered list would see churn
/// where there is none — and a diff nobody can read is a diff nobody checks.
#[tokio::test]
async fn the_document_is_stable() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let (node, _) = node_with_a_vm(&db).await?;
    let dbt: Arc<dyn LNVpsDb> = db.clone();

    let first = node_state(&dbt, &node).await?;
    let second = node_state(&dbt, &node).await?;
    assert_eq!(first.vms, second.vms);
    Ok(())
}

/// A VM whose row cannot be described — no SSH key, a missing image — fails the
/// whole document rather than being quietly dropped. Dropping it would tell the
/// node to destroy a running customer's VM because LNVPS could not describe it.
#[tokio::test]
async fn an_undescribable_vm_fails_the_document() -> Result<()> {
    let db = Arc::new(MockDb::empty());
    let (node, vm_id) = node_with_a_vm(&db).await?;
    let dbt: Arc<dyn LNVpsDb> = db.clone();

    {
        let mut vms = db.vms.lock().await;
        vms.get_mut(&vm_id).unwrap().ssh_key_id = None;
    }
    let err = node_state(&dbt, &node).await.unwrap_err();
    assert!(err.to_string().contains(&vm_id.to_string()), "{err}");
    Ok(())
}
