use crate::{DbResult, NostrDomain, NostrDomainHandle};
use async_trait::async_trait;

#[async_trait]
pub trait LNVPSNostrDb: Sync + Send {
    /// Get single handle for a domain
    async fn get_handle(&self, handle_id: u64) -> DbResult<NostrDomainHandle>;

    /// Get single handle for a domain
    async fn get_handle_by_name(&self, domain_id: u64, handle: &str)
    -> DbResult<NostrDomainHandle>;

    /// Insert a new handle
    async fn insert_handle(&self, handle: &NostrDomainHandle) -> DbResult<u64>;

    /// Update an existing domain handle
    async fn update_handle(&self, handle: &NostrDomainHandle) -> DbResult<()>;

    /// Delete handle entry
    async fn delete_handle(&self, handle_id: u64) -> DbResult<()>;

    /// List handles
    async fn list_handles(&self, domain_id: u64) -> DbResult<Vec<NostrDomainHandle>>;

    /// Get domain object by id
    async fn get_domain(&self, id: u64) -> DbResult<NostrDomain>;

    /// Get domain object by name
    async fn get_domain_by_name(&self, name: &str) -> DbResult<NostrDomain>;

    /// Get domain object by activation hash
    async fn get_domain_by_activation_hash(&self, hash: &str) -> DbResult<NostrDomain>;

    /// List domains owned by a user
    async fn list_domains(&self, owner_id: u64) -> DbResult<Vec<NostrDomain>>;

    /// Insert a new domain
    async fn insert_domain(&self, domain: &NostrDomain) -> DbResult<u64>;

    /// Delete a domain
    async fn delete_domain(&self, domain_id: u64) -> DbResult<()>;

    /// List all domains across all users (both active and disabled)
    async fn list_all_domains(&self) -> DbResult<Vec<NostrDomain>>;

    /// List all active (enabled) domains across all users
    async fn list_active_domains(&self) -> DbResult<Vec<NostrDomain>>;

    /// List all disabled domains across all users
    async fn list_disabled_domains(&self) -> DbResult<Vec<NostrDomain>>;

    /// Enable a domain by setting enabled=true and http_only=false (for DNS-based activation)
    async fn enable_domain_with_https(&self, domain_id: u64) -> DbResult<()>;

    /// Enable a domain by setting enabled=true but keeping http_only=true (for path-based activation)
    async fn enable_domain_http_only(&self, domain_id: u64) -> DbResult<()>;

    /// Disable a domain by setting enabled=false
    async fn disable_domain(&self, domain_id: u64) -> DbResult<()>;
}
