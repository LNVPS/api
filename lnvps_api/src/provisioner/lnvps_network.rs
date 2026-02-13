use crate::dns::{BasicRecord, DnsServer};
use crate::router::{ArpEntry, get_router};
use anyhow::{Context, anyhow};
use ipnetwork::IpNetwork;
use lnvps_api_common::op_fatal;
use lnvps_api_common::retry::OpResult;
use lnvps_db::{AccessPolicy, IpRange, LNVpsDb, NetworkAccessPolicy, VmIpAssignment};
use log::warn;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use try_procedure::{OpError, RetryPolicy, retry_async};

/// Network assignment tool for [super::LNVpsProvisioner]
#[derive(Clone)]
pub struct LNVpsNetworkProvisioner {
    db: Arc<dyn LNVpsDb>,
    /// DNS server to add entries to
    dns: Option<Arc<dyn DnsServer>>,
    /// Forward zone to add ip dns
    forward_zone_id: Option<String>,
    /// Retry policy to use when calling external services
    retry_policy: RetryPolicy,
}

impl LNVpsNetworkProvisioner {
    pub fn new(
        db: Arc<dyn LNVpsDb>,
        dns: Option<Arc<dyn DnsServer>>,
        forward_zone_id: Option<String>,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            db,
            dns,
            forward_zone_id,
            retry_policy,
        }
    }

    /// Create or Update access policy for a given ip assignment, does not save to database!
    pub async fn update_access_policy(
        &self,
        assignment: &mut VmIpAssignment,
        policy: &AccessPolicy,
    ) -> OpResult<()> {
        let ip = IpNetwork::from_str(&assignment.ip).map_err(|e| OpError::Fatal(anyhow!(e)))?;
        if matches!(policy.kind, NetworkAccessPolicy::StaticArp) && ip.is_ipv4() {
            let router = get_router(
                &self.db,
                policy
                    .router_id
                    .context("Cannot apply static arp policy with no router")?,
            )
            .await?;
            let vm = self.db.get_vm(assignment.vm_id).await?;
            let entry = ArpEntry::new(&vm, assignment, policy.interface.clone())?;

            let has_arp_ref = assignment.arp_ref.is_some();

            let arp = if has_arp_ref {
                router.update_arp_entry(&entry).await?
            } else {
                router.add_arp_entry(&entry).await?
            };

            if arp.id.is_none() {
                op_fatal!("ARP id was empty")
            }
            assignment.arp_ref = arp.id;
        }
        Ok(())
    }

    /// Remove an access policy for a given ip assignment, does not save to database!
    pub async fn remove_access_policy(
        &self,
        assignment: &mut VmIpAssignment,
        policy: &AccessPolicy,
    ) -> OpResult<()> {
        let ip = IpNetwork::from_str(&assignment.ip).map_err(|e| OpError::Fatal(anyhow!(e)))?;
        if matches!(policy.kind, NetworkAccessPolicy::StaticArp) && ip.is_ipv4() {
            let router = get_router(
                &self.db,
                policy
                    .router_id
                    .context("Cannot apply static arp policy with no router")?,
            )
            .await?;
            let id = if let Some(id) = &assignment.arp_ref {
                Some(id.clone())
            } else {
                warn!("ARP REF not found, using arp list");

                let ent = router.list_arp_entry().await?;
                if let Some(ent) = ent.iter().find(|e| e.address == assignment.ip) {
                    ent.id.clone()
                } else {
                    warn!("ARP entry not found, skipping");
                    None
                }
            };

            if let Some(id) = id
                && let Err(e) = retry_async(self.retry_policy.clone(), || async {
                    router.remove_arp_entry(&id).await
                })
                .await
            {
                warn!("Failed to remove arp entry after retries, skipping: {}", e);
            }

            assignment.arp_ref = None;
        }
        Ok(())
    }

    /// Delete DNS on the dns server, does not save to database!
    pub async fn remove_ip_dns(&self, assignment: &mut VmIpAssignment) -> OpResult<()> {
        // Delete forward/reverse dns
        if let Some(dns) = &self.dns {
            let range = self.db.get_ip_range(assignment.ip_range_id).await?;

            if let (Some(z), Some(_ref)) = (&range.reverse_zone_id, &assignment.dns_reverse_ref) {
                let rev = BasicRecord::reverse(assignment)?;

                if let Err(e) = retry_async(self.retry_policy.clone(), || async {
                    dns.delete_record(z, &rev).await
                })
                .await
                {
                    warn!("Failed to delete reverse record after retries: {}", e);
                }
                assignment.dns_reverse_ref = None;
                assignment.dns_reverse = None;
            }
            if let (Some(z), Some(_ref)) = (&self.forward_zone_id, &assignment.dns_forward_ref) {
                let fwd = BasicRecord::forward(assignment)?;

                if let Err(e) = retry_async(self.retry_policy.clone(), || async {
                    dns.delete_record(z, &fwd).await
                })
                .await
                {
                    warn!("Failed to delete forward record after retries: {}", e);
                }
                assignment.dns_forward_ref = None;
                assignment.dns_forward = None;
            }
        }
        Ok(())
    }

    /// Update DNS on the dns server, does not save to database!
    pub async fn update_forward_ip_dns(&self, assignment: &mut VmIpAssignment) -> OpResult<()> {
        if let (Some(z), Some(dns)) = (&self.forward_zone_id, &self.dns) {
            let fwd = BasicRecord::forward(assignment)?;
            let ret_fwd = retry_async(self.retry_policy.clone(), || async {
                if fwd.id.is_some() {
                    dns.update_record(z, &fwd).await
                } else {
                    dns.add_record(z, &fwd).await
                }
            })
            .await?;

            assignment.dns_forward = Some(ret_fwd.name);
            assignment.dns_forward_ref = Some(ret_fwd.id.context("Record id is missing")?);
        }
        Ok(())
    }

    /// Update DNS on the dns server, does not save to database!
    pub async fn update_reverse_ip_dns(&self, assignment: &mut VmIpAssignment) -> OpResult<()> {
        if let Some(dns) = &self.dns {
            let range = self.db.get_ip_range(assignment.ip_range_id).await?;
            if let Some(z) = &range.reverse_zone_id {
                let has_ref = assignment.dns_reverse_ref.is_some();
                let rev_record = if has_ref {
                    BasicRecord::reverse(assignment)?
                } else {
                    BasicRecord::reverse_to_fwd(assignment)?
                };

                let ret_rev = retry_async(self.retry_policy.clone(), || async {
                    if has_ref {
                        dns.update_record(z, &rev_record).await
                    } else {
                        dns.add_record(z, &rev_record).await
                    }
                })
                .await?;

                assignment.dns_reverse = Some(ret_rev.value);
                assignment.dns_reverse_ref = Some(ret_rev.id.context("Record id is missing")?);
            }
        }
        Ok(())
    }

    /// Delete all ip assignments for a given vm
    pub async fn delete_all_ip_assignments(&self, vm_id: u64) -> OpResult<()> {
        let mut ips = self.db.list_vm_ip_assignments(vm_id).await?;
        for ip in &mut ips {
            let range = self.db.get_ip_range(ip.ip_range_id).await?;
            self.delete_ip_assignment(ip, &range).await?;
        }
        Ok(())
    }

    /// Delete ip assignment
    pub async fn delete_ip_assignment(
        &self,
        ip: &mut VmIpAssignment,
        range: &IpRange,
    ) -> OpResult<()> {
        // remove access policy and dns
        self.rollback_ip_assignment_policy(ip, range).await?;
        // save arp/dns changes
        self.db.update_vm_ip_assignment(ip).await?;
        // mark as deleted
        self.db.delete_vm_ip_assignment(ip.id).await?;

        Ok(())
    }

    /// Rollback access policy and DNS for an IP assignment.
    /// This can be used to clean up resources that were created but not persisted to DB.
    pub async fn rollback_ip_assignment_policy(
        &self,
        ip: &mut VmIpAssignment,
        range: &IpRange,
    ) -> OpResult<()> {
        if let Some(ap) = range.access_policy_id {
            let ap = self.db.get_access_policy(ap).await?;
            // remove access policy
            self.remove_access_policy(ip, &ap).await?;
        }
        // remove dns
        self.remove_ip_dns(ip).await?;
        Ok(())
    }

    /// Validate IP assignment format and range
    pub fn validate_ip_assignment(
        &self,
        assignment: &VmIpAssignment,
        range: &IpRange,
    ) -> OpResult<()> {
        let provided_ip = assignment
            .ip
            .trim()
            .parse::<IpAddr>()
            .context("Invalid IP address format")?;

        let cidr = range
            .cidr
            .parse::<IpNetwork>()
            .context("Invalid CIDR format in IP range")?;

        if !cidr.contains(provided_ip) {
            op_fatal!("IP address is not within the specified IP range");
        }

        Ok(())
    }

    /// Save IP assignment to database (insert if id == 0, otherwise update)
    pub async fn persist_ip_assignment(&self, assignment: &mut VmIpAssignment) -> OpResult<()> {
        if assignment.id == 0 {
            let id = self.db.insert_vm_ip_assignment(assignment).await?;
            assignment.id = id;
        } else {
            self.db.update_vm_ip_assignment(assignment).await?;
        }
        Ok(())
    }

    /// Update access policy (ARP) for an IP assignment, does not save to database!
    pub async fn update_ip_assignment_access_policy(
        &self,
        assignment: &mut VmIpAssignment,
        range: &IpRange,
    ) -> OpResult<()> {
        if let Some(ap) = range.access_policy_id {
            let ap = self.db.get_access_policy(ap).await?;
            self.update_access_policy(assignment, &ap).await?;
        }
        Ok(())
    }

    /// Remove access policy (ARP) for an IP assignment, does not save to database!
    pub async fn remove_ip_assignment_access_policy(
        &self,
        assignment: &mut VmIpAssignment,
        range: &IpRange,
    ) -> OpResult<()> {
        if let Some(ap) = range.access_policy_id {
            let ap = self.db.get_access_policy(ap).await?;
            self.remove_access_policy(assignment, &ap).await?;
        }
        Ok(())
    }

    /// Convenience method: Update all external resources (ARP + DNS) for an IP assignment.
    /// Does NOT persist to database - use persist_ip_assignment() after this if needed.
    pub async fn update_ip_assignment_policy(
        &self,
        assignment: &mut VmIpAssignment,
        range: &IpRange,
    ) -> OpResult<()> {
        self.update_ip_assignment_access_policy(assignment, range)
            .await?;
        self.update_forward_ip_dns(assignment).await?;
        self.update_reverse_ip_dns(assignment).await?;
        Ok(())
    }

    /// Convenience method: Create IP assignment with all external resources and persist to DB.
    /// Combines validation, ARP setup, DNS setup, and DB persistence.
    pub async fn save_ip_assignment(&self, assignment: &mut VmIpAssignment) -> OpResult<()> {
        let range = self.db.get_ip_range(assignment.ip_range_id).await?;

        self.validate_ip_assignment(assignment, &range)?;
        self.update_ip_assignment_policy(assignment, &range)
            .await?;
        self.persist_ip_assignment(assignment).await?;

        Ok(())
    }
}
