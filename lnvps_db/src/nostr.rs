use async_trait::async_trait;
use crate::{NostrDomain, NostrDomainHandle};

#[async_trait]
pub trait LNVPSNostrDb: Sync + Send {
    /// Get single handle for a domain
    async fn get_handle(&self, handle_id: u64) -> anyhow::Result<NostrDomainHandle>;

    /// Get single handle for a domain
    async fn get_handle_by_name(&self, domain_id: u64, handle: &str) -> anyhow::Result<NostrDomainHandle>;

    /// Insert a new handle
    async fn insert_handle(&self, handle: &NostrDomainHandle) -> anyhow::Result<u64>;

    /// Update an existing domain handle
    async fn update_handle(&self, handle: &NostrDomainHandle) -> anyhow::Result<()>;

    /// Delete handle entry
    async fn delete_handle(&self, handle_id: u64) -> anyhow::Result<()>;

    /// List handles
    async fn list_handles(&self, domain_id: u64) -> anyhow::Result<Vec<NostrDomainHandle>>;

    /// Get domain object by id
    async fn get_domain(&self, id: u64) -> anyhow::Result<NostrDomain>;

    /// Get domain object by name
    async fn get_domain_by_name(&self, name: &str) -> anyhow::Result<NostrDomain>;

    /// List domains owned by a user
    async fn list_domains(&self, owner_id: u64) -> anyhow::Result<Vec<NostrDomain>>;

    /// Insert a new domain
    async fn insert_domain(&self, domain: &NostrDomain) -> anyhow::Result<u64>;

    /// Delete a domain
    async fn delete_domain(&self, domain_id: u64) -> anyhow::Result<()>;

    /// List all active (enabled) domains across all users
    async fn list_active_domains(&self) -> anyhow::Result<Vec<NostrDomain>>;
}
