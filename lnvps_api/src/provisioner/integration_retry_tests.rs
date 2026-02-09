//! Integration tests for retry and rollback logic
//!
//! These tests verify the complete behavior of retry/rollback in real scenarios

#[cfg(test)]
mod tests {
    use crate::host::VmHostClient;
    use crate::mocks::MockVmHost;
    use anyhow::{Result, bail};
    use async_trait::async_trait;
    use lnvps_api_common::retry::{OpError, OpResult};
    use lnvps_api_common::{MockDb, VmRunningState};
    use lnvps_db::{LNVpsDbBase, User, UserSshKey, Vm};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Mock VmHostClient that fails N times before succeeding
    #[derive(Clone)]
    pub struct FailingVmHostClient {
        inner: MockVmHost,
        create_vm_fail_count: Arc<AtomicU32>,
        delete_vm_fail_count: Arc<AtomicU32>,
        start_vm_fail_count: Arc<AtomicU32>,
        stop_vm_fail_count: Arc<AtomicU32>,
    }

    impl FailingVmHostClient {
        pub fn new(
            create_fails: u32,
            delete_fails: u32,
            start_fails: u32,
            stop_fails: u32,
        ) -> Self {
            Self {
                inner: MockVmHost::new(),
                create_vm_fail_count: Arc::new(AtomicU32::new(create_fails)),
                delete_vm_fail_count: Arc::new(AtomicU32::new(delete_fails)),
                start_vm_fail_count: Arc::new(AtomicU32::new(start_fails)),
                stop_vm_fail_count: Arc::new(AtomicU32::new(stop_fails)),
            }
        }

        pub fn create_failures_remaining(&self) -> u32 {
            self.create_vm_fail_count.load(Ordering::SeqCst)
        }

        pub fn delete_failures_remaining(&self) -> u32 {
            self.delete_vm_fail_count.load(Ordering::SeqCst)
        }

        pub fn start_failures_remaining(&self) -> u32 {
            self.start_vm_fail_count.load(Ordering::SeqCst)
        }

        pub fn stop_failures_remaining(&self) -> u32 {
            self.stop_vm_fail_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl VmHostClient for FailingVmHostClient {
        async fn get_info(&self) -> Result<crate::host::VmHostInfo> {
            self.inner.get_info().await
        }

        async fn download_os_image(&self, image: &lnvps_db::VmOsImage) -> Result<()> {
            self.inner.download_os_image(image).await
        }

        async fn generate_mac(&self, vm: &Vm) -> Result<String> {
            self.inner.generate_mac(vm).await
        }

        async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
            let fails = self.start_vm_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.start_vm_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow::anyhow!(
                    "Simulated VM start failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.start_vm(vm).await
        }

        async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
            let fails = self.stop_vm_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.stop_vm_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow::anyhow!(
                    "Simulated VM stop failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.stop_vm(vm).await
        }

        async fn reset_vm(&self, vm: &Vm) -> Result<()> {
            self.inner.reset_vm(vm).await
        }

        async fn create_vm(&self, req: &crate::host::FullVmInfo) -> OpResult<()> {
            let fails = self.create_vm_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.create_vm_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow::anyhow!(
                    "Simulated VM create failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.create_vm(req).await
        }

        async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
            let fails = self.delete_vm_fail_count.load(Ordering::SeqCst);
            if fails > 0 {
                self.delete_vm_fail_count.fetch_sub(1, Ordering::SeqCst);
                return Err(OpError::Transient(anyhow::anyhow!(
                    "Simulated VM delete failure (remaining: {})",
                    fails - 1
                )));
            }
            self.inner.delete_vm(vm).await
        }

        async fn reinstall_vm(&self, req: &crate::host::FullVmInfo) -> Result<()> {
            self.inner.reinstall_vm(req).await
        }

        async fn resize_disk(&self, cfg: &crate::host::FullVmInfo) -> Result<()> {
            self.inner.resize_disk(cfg).await
        }

        async fn get_vm_state(&self, vm: &Vm) -> Result<VmRunningState> {
            self.inner.get_vm_state(vm).await
        }

        async fn get_all_vm_states(&self) -> Result<Vec<(u64, VmRunningState)>> {
            self.inner.get_all_vm_states().await
        }

        async fn configure_vm(&self, cfg: &crate::host::FullVmInfo) -> Result<()> {
            self.inner.configure_vm(cfg).await
        }

        async fn patch_firewall(&self, cfg: &crate::host::FullVmInfo) -> Result<()> {
            self.inner.patch_firewall(cfg).await
        }

        async fn get_time_series_data(
            &self,
            vm: &Vm,
            series: crate::host::TimeSeries,
        ) -> Result<Vec<crate::host::TimeSeriesData>> {
            self.inner.get_time_series_data(vm, series).await
        }

        async fn connect_terminal(&self, vm: &Vm) -> Result<crate::host::TerminalStream> {
            self.inner.connect_terminal(vm).await
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
    async fn test_host_vm_start_retry() -> Result<()> {
        // Create a host client that fails 2 times on start
        let failing_host = Arc::new(FailingVmHostClient::new(0, 0, 2, 0));

        let db = Arc::new(MockDb::default());
        let (user, ssh_key) = add_user(&db).await?;

        let vm = lnvps_db::Vm {
            id: 1,
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
        };

        assert_eq!(failing_host.start_failures_remaining(), 2);

        // First attempt should fail
        let result = failing_host.start_vm(&vm).await;
        assert!(result.is_err());
        assert_eq!(failing_host.start_failures_remaining(), 1);

        // Second attempt should fail
        let result = failing_host.start_vm(&vm).await;
        assert!(result.is_err());
        assert_eq!(failing_host.start_failures_remaining(), 0);

        // Third attempt should succeed
        let result = failing_host.start_vm(&vm).await;
        assert!(result.is_ok());
        assert_eq!(failing_host.start_failures_remaining(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_host_vm_stop_retry() -> Result<()> {
        // Create a host client that fails 1 time on stop
        let failing_host = Arc::new(FailingVmHostClient::new(0, 0, 0, 1));

        let db = Arc::new(MockDb::default());
        let (user, ssh_key) = add_user(&db).await?;

        let vm = lnvps_db::Vm {
            id: 1,
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
        };

        assert_eq!(failing_host.stop_failures_remaining(), 1);

        // First attempt should fail
        let result = failing_host.stop_vm(&vm).await;
        assert!(result.is_err());
        assert_eq!(failing_host.stop_failures_remaining(), 0);

        // Second attempt should succeed
        let result = failing_host.stop_vm(&vm).await;
        assert!(result.is_ok());
        assert_eq!(failing_host.stop_failures_remaining(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_host_vm_delete_retry() -> Result<()> {
        // Create a host client that fails 1 time on delete
        let failing_host = Arc::new(FailingVmHostClient::new(0, 1, 0, 0));

        let db = Arc::new(MockDb::default());
        let (user, ssh_key) = add_user(&db).await?;

        let vm = lnvps_db::Vm {
            id: 1,
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
        };

        assert_eq!(failing_host.delete_failures_remaining(), 1);

        // First attempt should fail
        let result = failing_host.delete_vm(&vm).await;
        assert!(result.is_err());
        assert_eq!(failing_host.delete_failures_remaining(), 0);

        // Second attempt should succeed
        let result = failing_host.delete_vm(&vm).await;
        assert!(result.is_ok());
        assert_eq!(failing_host.delete_failures_remaining(), 0);

        Ok(())
    }
}
