use crate::db;
use crate::vm::VMSpec;
use anyhow::Error;
use sqlx::{MySqlPool, Row};

#[derive(Debug, Clone)]
pub struct Provisioner {
    db: MySqlPool,
}

impl Provisioner {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }

    /// Provision a new VM
    pub async fn provision(&self, spec: VMSpec) -> Result<db::Vm, Error> {
        todo!()
    }

    /// Insert/Fetch user id
    pub async fn upsert_user(&self, pubkey: &[u8; 32]) -> Result<u64, Error> {
        let res = sqlx::query("insert ignore into users(pubkey) values(?) returning id")
            .bind(pubkey.as_slice())
            .fetch_optional(&self.db)
            .await?;
        match res {
            None => sqlx::query("select id from users where pubkey = ?")
                .bind(pubkey.as_slice())
                .fetch_one(&self.db)
                .await?
                .try_get(0)
                .map_err(Error::new),
            Some(res) => res.try_get(0).map_err(Error::new),
        }
    }

    /// List VM's owned by a specific user
    pub async fn list_vms(&self, id: u64) -> Result<Vec<db::Vm>, Error> {
        sqlx::query_as("select * from vm where user_id = ?")
            .bind(&id)
            .fetch_all(&self.db)
            .await
            .map_err(Error::new)
    }
}
