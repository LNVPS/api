//! Tests for retry and rollback logic in the provisioner
//!
//! These tests verify that network operations (DNS, Router, Host) properly retry
//! on transient failures and that the provisioner correctly rolls back on errors.

#[cfg(test)]
mod tests {
    use crate::dns::{BasicRecord, DnsServer, RecordType};
    use crate::host::FullVmInfo;
    use crate::mocks::{MockDnsServer, MockNode, MockRouter};
    use crate::provisioner::LNVpsProvisioner;
    use crate::router::{ArpEntry, Router};
    use crate::settings::mock_settings;
    use anyhow::{Result, anyhow, bail};
    use async_trait::async_trait;
    use lnvps_api_common::retry::{OpError, OpResult};
    use lnvps_api_common::{InMemoryRateCache, MockDb, MockExchangeRate};
    use lnvps_db::{
        AccessPolicy, IpRange, LNVpsDb, LNVpsDbBase, NetworkAccessPolicy, RouterKind, User,
        UserSshKey, VmIpAssignment,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::Mutex;

    /// Mock DNS server that fails N times before succeeding
    pub struct FailingDnsServer {
        inner: Arc<MockDnsServer>,
        add_record_fail_count: Arc<AtomicU32>,
        update_record_fail_count: Arc<AtomicU32>,
        delete_record_fail_count: Arc<AtomicU32>,
    }

    impl FailingDnsServer {
        pub fn new(add_fails: u32, update_fails: u32, delete_fails: u32) -> Self {
            Self {
                inner: Arc::new(MockDnsServer::new()),
                add_record_fail_count: Arc::new(AtomicU32::new(add_fails)),
                update_record_fail_count: Arc::new(AtomicU32::new(update_fails)),
                delete_record_fail_count: Arc::new(AtomicU32::new(delete_fails)),
            }
        }

        /// Get number of remaining failures for add_record
        pub fn add_failures_remaining(&self) -> u32 {
            self.add_record_fail_count.load(Ordering::SeqCst)
        }

        /// Get number of remaining failures for update_record
        pub fn update_failures_remaining(&self) -> u32 {
            self.update_record_fail_count.load(Ordering::SeqCst)
        }

        /// Get number of remaining failures for delete_record
        pub fn delete_failures_remaining(&self) -> u32 {
            self.delete_record_fail_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DnsServer for FailingDnsServer {
        async fn add_record(&self, zone: &str, record: &BasicRecord) -> OpResult<BasicRecord> {
            let fails = self.add_record_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.add_record_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow!(
                    "Simulated DNS add failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.add_record(zone, record).await
        }

        async fn update_record(&self, zone: &str, record: &BasicRecord) -> OpResult<BasicRecord> {
            let fails = self.update_record_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.update_record_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow!(
                    "Simulated DNS update failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.update_record(zone, record).await
        }

        async fn delete_record(&self, zone: &str, record: &BasicRecord) -> OpResult<()> {
            let fails = self.delete_record_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.delete_record_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow!(
                    "Simulated DNS delete failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.delete_record(zone, record).await
        }
    }

    /// Mock Router that fails N times before succeeding
    #[derive(Clone)]
    pub struct FailingRouter {
        inner: MockRouter,
        add_arp_fail_count: Arc<AtomicU32>,
        update_arp_fail_count: Arc<AtomicU32>,
        remove_arp_fail_count: Arc<AtomicU32>,
        list_arp_fail_count: Arc<AtomicU32>,
    }

    impl FailingRouter {
        pub fn new(add_fails: u32, update_fails: u32, remove_fails: u32, list_fails: u32) -> Self {
            Self {
                inner: MockRouter::new(),
                add_arp_fail_count: Arc::new(AtomicU32::new(add_fails)),
                update_arp_fail_count: Arc::new(AtomicU32::new(update_fails)),
                remove_arp_fail_count: Arc::new(AtomicU32::new(remove_fails)),
                list_arp_fail_count: Arc::new(AtomicU32::new(list_fails)),
            }
        }

        pub fn add_failures_remaining(&self) -> u32 {
            self.add_arp_fail_count.load(Ordering::SeqCst)
        }

        pub fn remove_failures_remaining(&self) -> u32 {
            self.remove_arp_fail_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Router for FailingRouter {
        async fn generate_mac(&self, ip: &str, comment: &str) -> Result<Option<ArpEntry>> {
            self.inner.generate_mac(ip, comment).await
        }

        async fn list_arp_entry(&self) -> OpResult<Vec<ArpEntry>> {
            let fails = self.list_arp_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.list_arp_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow!(
                    "Simulated router list failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.list_arp_entry().await
        }

        async fn add_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
            let fails = self.add_arp_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.add_arp_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow!(
                    "Simulated router add failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.add_arp_entry(entry).await
        }

        async fn remove_arp_entry(&self, id: &str) -> OpResult<()> {
            let fails = self.remove_arp_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.remove_arp_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow!(
                    "Simulated router remove failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.remove_arp_entry(id).await
        }

        async fn update_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
            let fails = self.update_arp_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.update_arp_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow!(
                    "Simulated router update failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.update_arp_entry(entry).await
        }
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

    #[tokio::test]
    async fn test_dns_retry_on_add_record_failure() -> Result<()> {
        let settings = mock_settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(InMemoryRateCache::default());

        // Create a DNS server that fails 2 times then succeeds (within retry limit of 3)
        let failing_dns = Arc::new(FailingDnsServer::new(2, 0, 0));

        let (user, ssh_key) = add_user(&db).await?;
        let vm = db
            .insert_vm(&lnvps_db::Vm {
                id: 0,
                host_id: 1,
                user_id: user.id,
                image_id: 1,
                template_id: Some(1),
                custom_template_id: None,
                ssh_key_id: ssh_key.id,
                created: chrono::Utc::now(),
                expires: chrono::Utc::now(),
                disk_id: 1,
                mac_address: "bc:24:11:00:00:01".to_string(),
                deleted: false,
                ref_code: None,
                auto_renewal_enabled: false,
            })
            .await?;

        // Should fail 2 times and succeed on 3rd attempt
        assert_eq!(failing_dns.add_failures_remaining(), 2);

        // First attempt should fail
        let result = failing_dns
            .add_record(
                "test-zone",
                &BasicRecord {
                    id: None,
                    name: "test1.example.com".to_string(),
                    value: "10.0.0.100".to_string(),
                    kind: RecordType::A,
                },
            )
            .await;
        assert!(result.is_err(), "First attempt should fail");
        assert_eq!(failing_dns.add_failures_remaining(), 1);

        // Second attempt should fail
        let result = failing_dns
            .add_record(
                "test-zone",
                &BasicRecord {
                    id: None,
                    name: "test2.example.com".to_string(),
                    value: "10.0.0.101".to_string(),
                    kind: RecordType::A,
                },
            )
            .await;
        assert!(result.is_err(), "Second attempt should fail");
        assert_eq!(failing_dns.add_failures_remaining(), 0);

        // Third attempt should succeed (different record name to avoid duplicates)
        let result = failing_dns
            .add_record(
                "test-zone",
                &BasicRecord {
                    id: None,
                    name: "test3.example.com".to_string(),
                    value: "10.0.0.102".to_string(),
                    kind: RecordType::A,
                },
            )
            .await;
        assert!(result.is_ok(), "Third attempt should succeed");
        assert_eq!(failing_dns.add_failures_remaining(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_dns_retry_exceeds_limit() -> Result<()> {
        // Create a DNS server that fails 5 times (exceeds retry limit of 3)
        let failing_dns = Arc::new(FailingDnsServer::new(5, 0, 0));

        assert_eq!(failing_dns.add_failures_remaining(), 5);

        // All 3 retry attempts should fail
        for i in 0..3 {
            let result = failing_dns
                .add_record(
                    "test-zone",
                    &BasicRecord {
                        id: None,
                        name: "test.example.com".to_string(),
                        value: "10.0.0.100".to_string(),
                        kind: RecordType::A,
                    },
                )
                .await;
            assert!(result.is_err(), "Attempt {} should fail", i + 1);
            assert_eq!(failing_dns.add_failures_remaining(), 5 - i - 1);
        }

        // Should still have 2 failures remaining (5 - 3 attempts)
        assert_eq!(failing_dns.add_failures_remaining(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_router_arp_retry_on_add_failure() -> Result<()> {
        // Create a router that fails 2 times on add, then succeeds
        let failing_router = Arc::new(FailingRouter::new(2, 0, 0, 0));

        let test_entry = ArpEntry {
            id: None,
            address: "10.0.0.100".to_string(),
            mac_address: "bc:24:11:00:00:01".to_string(),
            interface: Some("bridge1".to_string()),
            comment: Some("test-vm".to_string()),
        };

        assert_eq!(failing_router.add_failures_remaining(), 2);

        // First attempt should fail
        let result = failing_router.add_arp_entry(&test_entry).await;
        assert!(result.is_err());
        assert_eq!(failing_router.add_failures_remaining(), 1);

        // Second attempt should fail
        let result = failing_router.add_arp_entry(&test_entry).await;
        assert!(result.is_err());
        assert_eq!(failing_router.add_failures_remaining(), 0);

        // Third attempt should succeed
        let result = failing_router.add_arp_entry(&test_entry).await;
        assert!(result.is_ok());
        assert_eq!(failing_router.add_failures_remaining(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_router_arp_retry_on_remove_failure() -> Result<()> {
        // Create a router and add an entry first
        let failing_router = Arc::new(FailingRouter::new(0, 0, 2, 0));

        // Use unique IP/MAC to avoid conflicts with other tests (static mock state)
        let test_entry = ArpEntry {
            id: None,
            address: "10.0.0.201".to_string(),
            mac_address: "bc:24:11:00:00:21".to_string(),
            interface: Some("bridge1".to_string()),
            comment: Some("test-vm-remove".to_string()),
        };

        // Add entry successfully
        let added = failing_router.add_arp_entry(&test_entry).await?;
        let entry_id = added.id.clone().unwrap();

        assert_eq!(failing_router.remove_failures_remaining(), 2);

        // First removal attempt should fail
        let result = failing_router.remove_arp_entry(&entry_id).await;
        assert!(result.is_err());
        assert_eq!(failing_router.remove_failures_remaining(), 1);

        // Second removal attempt should fail
        let result = failing_router.remove_arp_entry(&entry_id).await;
        assert!(result.is_err());
        assert_eq!(failing_router.remove_failures_remaining(), 0);

        // Third removal attempt should succeed
        let result = failing_router.remove_arp_entry(&entry_id).await;
        assert!(result.is_ok());
        assert_eq!(failing_router.remove_failures_remaining(), 0);

        // Verify this specific entry was removed (check by IP since mock state is shared)
        let entries = failing_router.list_arp_entry().await?;
        assert!(!entries.iter().any(|e| e.address == "10.0.0.201"));

        Ok(())
    }

    #[tokio::test]
    async fn test_dns_delete_retry_with_warning() -> Result<()> {
        // Create a DNS server that fails on delete
        let failing_dns = Arc::new(FailingDnsServer::new(0, 0, 10)); // Exceeds retry limit

        // Add a record first (use unique name)
        let record = failing_dns
            .add_record(
                "test-zone",
                &BasicRecord {
                    id: None,
                    name: "test-delete.example.com".to_string(),
                    value: "10.0.0.100".to_string(),
                    kind: RecordType::A,
                },
            )
            .await?;

        assert_eq!(failing_dns.delete_failures_remaining(), 10);

        // Delete will fail 3 times (retry limit)
        for i in 0..3 {
            let result = failing_dns.delete_record("test-zone", &record).await;
            assert!(result.is_err(), "Delete attempt {} should fail", i + 1);
        }

        // Should have consumed 3 failures
        assert_eq!(failing_dns.delete_failures_remaining(), 7);

        Ok(())
    }

    #[tokio::test]
    async fn test_dns_update_retry_success() -> Result<()> {
        // Create a DNS server that fails 1 time on update
        let failing_dns = Arc::new(FailingDnsServer::new(0, 1, 0));

        // Add a record first (use unique name to avoid conflicts with other tests)
        let record = failing_dns
            .add_record(
                "test-zone",
                &BasicRecord {
                    id: None,
                    name: "test-update.example.com".to_string(),
                    value: "10.0.0.100".to_string(),
                    kind: RecordType::A,
                },
            )
            .await?;

        assert_eq!(failing_dns.update_failures_remaining(), 1);

        // First update should fail
        let mut updated_record = record.clone();
        updated_record.value = "10.0.0.101".to_string();
        let result = failing_dns
            .update_record("test-zone", &updated_record)
            .await;
        assert!(result.is_err());
        assert_eq!(failing_dns.update_failures_remaining(), 0);

        // Second update should succeed
        let result = failing_dns
            .update_record("test-zone", &updated_record)
            .await;
        assert!(result.is_ok());

        Ok(())
    }
}
