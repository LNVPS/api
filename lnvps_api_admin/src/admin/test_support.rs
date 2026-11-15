use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::Permission;
use lnvps_api_common::{
    ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache, WorkCommander,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, LNVpsDbBase};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub struct Fixture {
    pub mock: Arc<MockDb>,
    pub commander: Arc<ChannelWorkCommander>,
    pub state: RouterState,
    pub vm_id: u64,
    pub owner_id: u64,
}

pub async fn fixture() -> Fixture {
    let mock = Arc::new(MockDb::default());
    let owner_id = mock.upsert_user(&[3u8; 32]).await.unwrap();
    let mut vm = MockDb::mock_vm();
    vm.user_id = owner_id;
    vm.ssh_key_id = None;
    let vm_id = mock.insert_vm(&vm).await.unwrap();
    let commander = Arc::new(ChannelWorkCommander::new());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    let state = RouterState {
        node_control: None,
        db,
        work_commander: commander.clone(),
        feedback: None,
        vm_state_cache: VmStateCache::new(),
        exchange: Arc::new(MockExchangeRate::default()),
        vat: VatClient::new(),
        chain: None,
    };
    Fixture {
        mock,
        commander,
        state,
        vm_id,
        owner_id,
    }
}

pub fn admin(user_id: u64, grants: &[(AdminResource, AdminAction)]) -> AdminAuth {
    AdminAuth {
        user_id,
        pubkey: vec![1u8; 32],
        permissions: grants
            .iter()
            .map(|(resource, action)| Permission {
                resource: *resource,
                action: *action,
            })
            .collect(),
        nip98_auth: None,
    }
}

impl Fixture {
    pub fn break_audit_log(&self) {
        self.mock.fail_audit_writes.store(true, Ordering::SeqCst);
    }

    pub async fn audit_actions(&self) -> Vec<String> {
        self.mock
            .audit_log
            .lock()
            .await
            .iter()
            .map(|e| e.action.clone())
            .collect()
    }

    pub async fn queued_jobs(&self) -> usize {
        match tokio::time::timeout(Duration::from_millis(50), self.commander.recv()).await {
            Ok(Ok(jobs)) => jobs.len(),
            _ => 0,
        }
    }
}
