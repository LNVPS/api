use crate::db;
use crate::vm::VMSpec;
use anyhow::Error;
use sqlx::MySqlPool;

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
}
