use crate::data_migration::DataMigration;
use crate::router::get_router;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use log::{info, warn};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct ArpRefFixerDataMigration {
    db: Arc<dyn LNVpsDb>,
}

impl ArpRefFixerDataMigration {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }
}

impl DataMigration for ArpRefFixerDataMigration {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let db = self.db.clone();
        Box::pin(async move {
            info!("Starting ARP reference fixer migration");

            // Get all routers and enumerate their ARP entries
            let routers = db.list_routers().await?;
            let mut fixed_count = 0;

            for router in routers {
                info!("Processing router {} ({})", router.id, router.name);

                match get_router(&db, router.id).await {
                    Ok(router_client) => {
                        match router_client.list_arp_entry().await {
                            Ok(arp_entries) => {
                                info!(
                                    "Found {} ARP entries on router {}",
                                    arp_entries.len(),
                                    router.id
                                );

                                for arp_entry in arp_entries {
                                    if let Some(arp_id) = &arp_entry.id {
                                        // Try to find IP assignment for this ARP entry
                                        match db
                                            .get_vm_ip_assignment_by_ip(&arp_entry.address)
                                            .await
                                        {
                                            Ok(mut assignment) => {
                                                // Check if the ARP ref needs updating
                                                let needs_update = assignment
                                                    .arp_ref
                                                    .as_ref()
                                                    .map(|current_ref| current_ref != arp_id)
                                                    .unwrap_or(true);

                                                if needs_update {
                                                    info!(
                                                        "Updating ARP ref for IP {} from {:?} to {}",
                                                        assignment.ip, assignment.arp_ref, arp_id
                                                    );
                                                    assignment.arp_ref = Some(arp_id.clone());

                                                    // Update in database
                                                    if let Err(e) = db
                                                        .update_vm_ip_assignment(&assignment)
                                                        .await
                                                    {
                                                        warn!(
                                                            "Failed to update ARP ref for IP {}: {}",
                                                            assignment.ip, e
                                                        );
                                                    } else {
                                                        fixed_count += 1;
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                // IP not found in assignments, skip
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to list ARP entries for router {}: {}", router.id, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get router {}: {}", router.id, e);
                    }
                }
            }

            info!(
                "ARP reference fixer migration completed, fixed {} references",
                fixed_count
            );
            Ok(())
        })
    }
}
