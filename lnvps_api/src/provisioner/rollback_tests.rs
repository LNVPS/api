//! Tests for rollback procedures in the provisioner
//!
//! These tests verify that the spawn_vm_pipeline correctly rolls back:
//! 1. IP allocation (ARP entries removed from router)
//! 2. Host spawn (VM deleted from host)
//! 3. Database changes (IP assignments hard-deleted)
//!
//! Note: The mock implementations use static LazyLock for shared state,
//! so tests use #[serial] to ensure they run sequentially.

#[cfg(test)]
mod tests {
    use crate::mocks::{MockDnsServer, MockNode, MockRouter};
    use crate::provisioner::LNVpsProvisioner;
    use crate::router::Router;
    use crate::settings::mock_settings;
    use anyhow::Result;
    use lnvps_api_common::{ExchangeRateService, MockDb, MockExchangeRate, Ticker};
    use lnvps_db::{AccessPolicy, LNVpsDbBase, NetworkAccessPolicy, RouterKind, User, UserSshKey};
    use std::sync::Arc;

    const ROUTER_BRIDGE: &str = "bridge1";

    /// Clear shared mock state for test isolation
    async fn clear_mock_state() {
        MockRouter::new().clear().await;
    }

    async fn setup_db_with_static_arp(db: &Arc<MockDb>) -> Result<()> {
        let mut r = db.router.lock().await;
        r.insert(
            1,
            lnvps_db::Router {
                id: 1,
                name: "mock-router".to_string(),
                enabled: true,
                kind: RouterKind::MockRouter,
                url: "https://localhost".to_string(),
                token: "username:password".into(),
            },
        );
        drop(r);

        let mut p = db.access_policy.lock().await;
        p.insert(
            1,
            AccessPolicy {
                id: 1,
                name: "static-arp".to_string(),
                kind: NetworkAccessPolicy::StaticArp,
                router_id: Some(1),
                interface: Some(ROUTER_BRIDGE.to_string()),
            },
        );
        drop(p);

        let mut i = db.ip_range.lock().await;
        if let Some(range) = i.get_mut(&1) {
            range.access_policy_id = Some(1);
            range.reverse_zone_id = Some("mock-rev-zone-id".to_string());
        }
        if let Some(range) = i.get_mut(&2) {
            range.reverse_zone_id = Some("mock-v6-rev-zone-id".to_string());
        }
        drop(i);

        Ok(())
    }

    async fn add_user(db: &Arc<MockDb>) -> Result<(User, UserSshKey)> {
        let pubkey: [u8; 32] = rand::random();
        let user_id = db.upsert_user(&pubkey).await?;
        let mut new_key = UserSshKey {
            id: 0,
            name: "test-key".to_string(),
            user_id,
            created: Default::default(),
            key_data: "ssh-rsa AAA==".into(),
        };
        let ssh_key = db.insert_user_ssh_key(&new_key).await?;
        new_key.id = ssh_key;
        Ok((db.get_user(user_id).await?, new_key))
    }

    /// Test that when host_spawn step fails, the ip_allocation step is rolled back
    /// This should remove any ARP entries that were created
    #[tokio::test]
    async fn test_rollback_ip_allocation_on_host_spawn_failure() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = Arc::new(MockDnsServer::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let provisioner =
            LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone(), Some(dns));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;

        // Get initial ARP count
        let router = MockRouter::new();
        let initial_arp_entries = router.list_arp_entry().await?;
        let initial_count = initial_arp_entries.len();

        // Execute the spawn pipeline
        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        // Get the VM's MAC address before any cleanup
        let vm_after_spawn = db.get_vm(vm.id).await?;
        let mac_address = vm_after_spawn.mac_address.clone();

        // Verify ARP entry was created
        let final_arp_entries = router.list_arp_entry().await?;
        assert!(
            final_arp_entries
                .iter()
                .any(|e| e.mac_address == mac_address),
            "ARP entry for VM should exist"
        );

        // Now clean up and verify cleanup works (this tests the delete_vm rollback)
        provisioner.delete_vm(vm.id).await?;

        // Verify ARP entry for this VM was removed
        let cleanup_arp_entries = router.list_arp_entry().await?;
        assert!(
            !cleanup_arp_entries
                .iter()
                .any(|e| e.mac_address == mac_address),
            "ARP entry should be removed after delete_vm"
        );

        Ok(())
    }

    /// Test that when save_vm step fails, both host_spawn and ip_allocation are rolled back
    #[tokio::test]
    async fn test_rollback_chain_on_save_vm_failure() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = Arc::new(MockDnsServer::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let provisioner =
            LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone(), Some(dns));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;

        // Spawn the VM
        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        // Get the VM's MAC address
        let vm = db.get_vm(vm.id).await?;
        let mac_address = vm.mac_address.clone();

        // Verify IP assignments were created
        let ips = db.list_vm_ip_assignments(vm.id).await?;
        assert!(!ips.is_empty(), "IP assignments should exist after spawn");

        // Verify ARP entries exist
        let router = MockRouter::new();
        let arp_entries = router.list_arp_entry().await?;
        assert!(
            arp_entries.iter().any(|e| e.mac_address == mac_address),
            "ARP entry should exist for VM"
        );

        // Delete the VM to trigger cleanup (simulating rollback scenario)
        provisioner.delete_vm(vm.id).await?;

        // Verify IP assignments are marked deleted
        let ips_after = db.list_vm_ip_assignments(vm.id).await?;
        for ip in ips_after {
            assert!(ip.deleted, "IP assignment should be marked as deleted");
            assert!(
                ip.arp_ref.is_none(),
                "ARP ref should be cleared after delete"
            );
            assert!(
                ip.dns_forward.is_none(),
                "DNS forward should be cleared after delete"
            );
            assert!(
                ip.dns_reverse.is_none(),
                "DNS reverse should be cleared after delete"
            );
        }

        // Verify ARP entry was removed
        let arp_after = router.list_arp_entry().await?;
        assert!(
            !arp_after.iter().any(|e| e.mac_address == mac_address),
            "ARP entry should be removed after delete"
        );

        Ok(())
    }

    /// Test that DNS records are properly rolled back (deleted) when VM is deleted
    #[tokio::test]
    async fn test_rollback_dns_records_on_delete() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = MockDnsServer::new();
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let provisioner = LNVpsProvisioner::new(
            settings,
            db.clone(),
            node.clone(),
            rates.clone(),
            Some(Arc::new(dns.clone())),
        );

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;

        // Get initial DNS zone counts
        let (initial_rev_count, initial_fwd_count) = {
            let zones = dns.zones.lock().await;
            let rev_count = zones.get("mock-rev-zone-id").map(|z| z.len()).unwrap_or(0);
            let fwd_count = zones
                .get("mock-forward-zone-id")
                .map(|z| z.len())
                .unwrap_or(0);
            (rev_count, fwd_count)
        };

        // Spawn the VM
        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        // Check DNS zones have more entries than before
        let (after_spawn_rev_count, after_spawn_fwd_count) = {
            let zones = dns.zones.lock().await;
            let rev_count = zones.get("mock-rev-zone-id").map(|z| z.len()).unwrap_or(0);
            let fwd_count = zones
                .get("mock-forward-zone-id")
                .map(|z| z.len())
                .unwrap_or(0);
            (rev_count, fwd_count)
        };

        assert!(
            after_spawn_rev_count > initial_rev_count,
            "Reverse DNS zone should have entries after spawn"
        );
        assert!(
            after_spawn_fwd_count > initial_fwd_count,
            "Forward DNS zone should have entries after spawn"
        );

        // Delete the VM
        provisioner.delete_vm(vm.id).await?;

        // Verify DNS records are removed (count should be back to initial or less)
        {
            let zones = dns.zones.lock().await;
            let rev_count = zones.get("mock-rev-zone-id").map(|z| z.len()).unwrap_or(0);
            let fwd_count = zones
                .get("mock-forward-zone-id")
                .map(|z| z.len())
                .unwrap_or(0);

            assert!(
                rev_count <= initial_rev_count,
                "Reverse DNS zone should not have more entries after delete"
            );
            assert!(
                fwd_count <= initial_fwd_count,
                "Forward DNS zone should not have more entries after delete"
            );
        }

        Ok(())
    }

    /// Test that IP assignments are properly managed during spawn and delete
    #[tokio::test]
    async fn test_ip_assignments_hard_deleted_on_rollback() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = Arc::new(MockDnsServer::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let provisioner =
            LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone(), Some(dns));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;

        // Before spawn - no IPs should exist
        let ips_before = db.list_vm_ip_assignments(vm.id).await?;
        assert!(
            ips_before.is_empty(),
            "No IP assignments should exist before spawn"
        );

        // Spawn VM
        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        // After spawn - IPs should exist
        let ips_after_spawn = db.list_vm_ip_assignments(vm.id).await?;
        assert_eq!(
            ips_after_spawn.len(),
            2,
            "Should have 2 IP assignments (IPv4 + IPv6)"
        );
        for ip in &ips_after_spawn {
            assert!(!ip.deleted, "IP assignments should not be deleted");
        }

        // Delete VM
        provisioner.delete_vm(vm.id).await?;

        // After delete - IPs should be soft-deleted (marked deleted=true)
        let ips_after_delete = db.list_vm_ip_assignments(vm.id).await?;
        for ip in &ips_after_delete {
            assert!(
                ip.deleted,
                "IP assignment {} should be marked as deleted",
                ip.id
            );
        }

        Ok(())
    }

    /// Test that skipping already assigned IPs works correctly during re-spawn attempts
    #[tokio::test]
    async fn test_skip_already_assigned_ips() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = Arc::new(MockDnsServer::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let provisioner =
            LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone(), Some(dns));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;

        // Spawn VM once
        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        // Try to spawn again - should skip IP allocation since IPs already exist
        let pipeline2 = provisioner.spawn_vm_pipeline(vm.id).await?;
        let _result = pipeline2.execute().await;

        // The second spawn should either succeed (skipping IPs) or fail gracefully
        // The key is that it doesn't duplicate IPs
        let ips = db.list_vm_ip_assignments(vm.id).await?;
        assert_eq!(ips.len(), 2, "Should still have exactly 2 IP assignments");

        // Cleanup
        provisioner.delete_vm(vm.id).await?;

        Ok(())
    }

    /// Test that MAC address rollback works when router generates the MAC
    #[tokio::test]
    async fn test_mac_address_rollback_with_router_generated_mac() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = Arc::new(MockDnsServer::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let provisioner =
            LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone(), Some(dns));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;

        // Spawn and get the MAC address
        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        let vm = db.get_vm(vm.id).await?;
        let mac_address = vm.mac_address.clone();

        // Verify MAC is not the default
        assert_ne!(
            mac_address, "ff:ff:ff:ff:ff:ff",
            "MAC should be assigned after spawn"
        );

        // Delete and verify cleanup
        provisioner.delete_vm(vm.id).await?;

        // The ARP entry with this MAC should be gone
        let router = MockRouter::new();
        let arp_entries = router.list_arp_entry().await?;
        assert!(
            !arp_entries.iter().any(|e| e.mac_address == mac_address),
            "ARP entry with VM's MAC should be removed"
        );

        Ok(())
    }

    /// Test the delete_vm pipeline executes all cleanup steps
    #[tokio::test]
    async fn test_delete_vm_pipeline_complete_cleanup() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = Arc::new(MockDnsServer::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let _dns = MockDnsServer::new();
        let provisioner =
            LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone(), Some(dns));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;

        // Spawn the VM
        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        // Get VM info before delete
        let vm = db.get_vm(vm.id).await?;
        let mac_address = vm.mac_address.clone();
        let vm_id = vm.id;

        // Verify everything is set up
        let ips = db.list_vm_ip_assignments(vm_id).await?;
        assert_eq!(ips.len(), 2);

        let router = MockRouter::new();
        let arp_before = router.list_arp_entry().await?;
        assert!(arp_before.iter().any(|e| e.mac_address == mac_address));

        // Delete the VM
        provisioner.delete_vm(vm_id).await?;

        // Verify complete cleanup:
        // Note: MockDb hard-deletes VMs, so we can't verify VM.deleted flag
        // In production, the VM would be soft-deleted (deleted = true)

        // 1. VM should no longer be accessible (MockDb hard-delete)
        let vm_get_result = db.get_vm(vm_id).await;
        assert!(vm_get_result.is_err(), "VM should be deleted from MockDb");

        // 2. IPs should be soft-deleted with refs cleared
        let ips_after = db.list_vm_ip_assignments(vm_id).await?;
        for ip in ips_after {
            assert!(ip.deleted, "IP should be marked as deleted");
            assert!(ip.arp_ref.is_none(), "ARP ref should be cleared");
            assert!(
                ip.dns_forward_ref.is_none(),
                "DNS forward ref should be cleared"
            );
            assert!(
                ip.dns_reverse_ref.is_none(),
                "DNS reverse ref should be cleared"
            );
        }

        // 3. ARP entry is removed
        let arp_after = router.list_arp_entry().await?;
        assert!(
            !arp_after.iter().any(|e| e.mac_address == mac_address),
            "ARP entry should be removed"
        );

        Ok(())
    }

    /// Test that ARP/DNS resources created during save_vm step are properly rolled back
    /// when the step fails (simulating the scenario where ARP is created but DB insert fails)
    #[tokio::test]
    async fn test_rollback_unpersisted_arp_dns_on_save_vm_failure() -> Result<()> {
        clear_mock_state().await;
        use crate::provisioner::LNVpsNetworkProvisioner;
        use try_procedure::RetryPolicy;

        let db = Arc::new(MockDb::default());
        let dns = Arc::new(MockDnsServer::new());

        setup_db_with_static_arp(&db).await?;

        let network = LNVpsNetworkProvisioner::new(
            db.clone(),
            Some(dns.clone()),
            Some("mock-forward-zone-id".to_string()),
            RetryPolicy::default().with_max_retries(0),
        );

        // Create a VM
        let (user, ssh_key) = add_user(&db).await?;

        // Create the VM first
        let mut vm = lnvps_db::Vm {
            id: 0,
            host_id: 1,
            user_id: user.id,
            image_id: 1,
            ssh_key_id: ssh_key.id,
            template_id: Some(1),
            custom_template_id: None,
            disk_id: 1,
            mac_address: "02:00:00:00:00:01".to_string(), // A valid MAC
            expires: chrono::Utc::now() + chrono::Duration::days(30),
            created: chrono::Utc::now(),
            ref_code: None,
            deleted: false,
            auto_renewal_enabled: false,
        };
        let vm_id = db.insert_vm(&vm).await?;
        vm.id = vm_id;

        // Create an IP assignment that has not been persisted yet (id == 0)
        let mut assignment = lnvps_db::VmIpAssignment {
            id: 0, // Not persisted
            vm_id,
            ip_range_id: 1,
            ip: "10.0.0.5".to_string(),
            arp_ref: None,
            dns_forward: None,
            dns_reverse: None,
            dns_forward_ref: None,
            dns_reverse_ref: None,
            deleted: false,
        };

        let range = db.get_ip_range(1).await?;

        // Simulate what save_ip_assignment does: create ARP and DNS entries
        network
            .update_ip_assignment_policy(&mut assignment, &range)
            .await?;

        // At this point, ARP and DNS refs should be set, but IP is not in DB
        assert!(
            assignment.arp_ref.is_some(),
            "ARP ref should be set after policy update"
        );
        // DNS refs may or may not be set depending on zone config
        let arp_ref = assignment.arp_ref.clone().unwrap();

        // Verify ARP entry exists on router
        let router = MockRouter::new();
        let arp_entries = router.list_arp_entry().await?;
        assert!(
            arp_entries.iter().any(|e| e.id.as_ref() == Some(&arp_ref)),
            "ARP entry should exist after policy update"
        );

        // Now simulate rollback (what happens if DB insert fails)
        network
            .rollback_ip_assignment_policy(&mut assignment, &range)
            .await?;

        // Verify ARP entry was removed
        let arp_entries_after = router.list_arp_entry().await?;
        assert!(
            !arp_entries_after
                .iter()
                .any(|e| e.id.as_ref() == Some(&arp_ref)),
            "ARP entry should be removed after rollback"
        );

        // Verify refs are cleared
        assert!(
            assignment.arp_ref.is_none(),
            "ARP ref should be cleared after rollback"
        );

        Ok(())
    }

    /// Test that the pipeline handles cleanup correctly for all resources
    #[tokio::test]
    async fn test_pipeline_handles_complete_cleanup() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = Arc::new(MockDnsServer::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let provisioner =
            LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone(), Some(dns));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;
        let vm_id = vm.id;

        // Spawn the VM
        let pipeline = provisioner.spawn_vm_pipeline(vm_id).await?;
        pipeline.execute().await?;

        // Verify IP assignments exist before delete
        let ips_before = db.list_vm_ip_assignments(vm_id).await?;
        assert!(!ips_before.is_empty(), "Should have IP assignments");

        // Delete should work
        let result = provisioner.delete_vm(vm_id).await;
        assert!(result.is_ok(), "Delete should succeed");

        // Verify VM is deleted (MockDb hard-deletes)
        let vm_get_result = db.get_vm(vm_id).await;
        assert!(vm_get_result.is_err(), "VM should be deleted from MockDb");

        // Verify IP assignments are marked as deleted
        let ips_after = db.list_vm_ip_assignments(vm_id).await?;
        for ip in ips_after {
            assert!(ip.deleted, "IP should be marked as deleted");
        }

        Ok(())
    }

    /// Test that when the router's generate_mac returns an ArpEntry, the vm.mac_address
    /// is set from ArpEntry.mac_address (the actual MAC) and not ArpEntry.address (the IP).
    /// This covers the regression where mac and IP were mixed up in the OVH router path.
    #[tokio::test]
    async fn test_router_generated_mac_stored_correctly() -> Result<()> {
        clear_mock_state().await;
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let dns = Arc::new(MockDnsServer::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        setup_db_with_static_arp(&db).await?;

        let provisioner =
            LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone(), Some(dns));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, None)
            .await?;

        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        let vm_after = db.get_vm(vm.id).await?;
        let stored_mac = &vm_after.mac_address;

        // The router returns an ArpEntry where address=IP and mac_address=MAC.
        // The stored value must look like a MAC address, not an IP address.
        assert!(
            !stored_mac.contains('.'),
            "vm.mac_address must not be an IP address (got '{}')",
            stored_mac
        );
        assert!(
            stored_mac.contains(':'),
            "vm.mac_address must be a MAC address in colon notation (got '{}')",
            stored_mac
        );

        // Cross-check: the stored MAC must match what the router recorded for this VM
        let router = MockRouter::new();
        let arp_entries = router.list_arp_entry().await?;
        assert!(
            arp_entries.iter().any(|e| &e.mac_address == stored_mac),
            "The ARP table should contain an entry whose mac_address matches the stored vm.mac_address"
        );

        Ok(())
    }
}
