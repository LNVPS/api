use anyhow::Result;
use k8s_openapi::api::networking::v1::{
    Ingress, IngressBackend, IngressRule, IngressServiceBackend, IngressSpec, IngressTLS,
    ServiceBackendPort,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use lnvps_db::NostrDomain;
use log::{error, info};
use std::collections::BTreeMap;

use crate::{Context, Settings};

/// Create an HTTP-only Ingress resource for pending activation domains
fn create_http_only_ingress(domains: &[NostrDomain], settings: &Settings) -> Ingress {
    let mut annotations = BTreeMap::new();

    // Add configurable ingress class
    annotations.insert(
        "kubernetes.io/ingress.class".to_string(),
        settings
            .ingress_class
            .as_deref()
            .unwrap_or("nginx")
            .to_string(),
    );

    // Disable SSL redirect for HTTP-only domains
    annotations.insert(
        "nginx.ingress.kubernetes.io/ssl-redirect".to_string(),
        "false".to_string(),
    );

    // Add any custom annotations from configuration
    if let Some(custom_annotations) = &settings.annotations {
        for (key, value) in custom_annotations {
            annotations.insert(key.clone(), value.clone());
        }
    }

    // Create rules for each HTTP-only domain
    let rules: Vec<IngressRule> = domains
        .iter()
        .map(|domain| IngressRule {
            host: Some(domain.name.clone()),
            http: Some(k8s_openapi::api::networking::v1::HTTPIngressRuleValue {
                paths: vec![k8s_openapi::api::networking::v1::HTTPIngressPath {
                    path: Some("/".to_string()),
                    path_type: "Prefix".to_string(),
                    backend: IngressBackend {
                        service: Some(IngressServiceBackend {
                            name: settings
                                .service_name
                                .as_deref()
                                .unwrap_or("lnvps-nostr")
                                .to_string(),
                            port: Some(ServiceBackendPort {
                                number: None,
                                name: Some(
                                    settings.port_name.as_deref().unwrap_or("http").to_string(),
                                ),
                            }),
                        }),
                        resource: None,
                    },
                }],
            }),
        })
        .collect();

    let ingress_spec = IngressSpec {
        tls: None, // No TLS for HTTP-only domains
        rules: if rules.is_empty() { None } else { Some(rules) },
        ..Default::default()
    };

    // Create labels with domain count
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "lnvps-nostr".to_string());
    labels.insert("managed-by".to_string(), "lnvps-operator".to_string());
    labels.insert("component".to_string(), "nostr-domains-http".to_string());
    labels.insert("domain-count".to_string(), domains.len().to_string());

    Ingress {
        metadata: ObjectMeta {
            name: Some("lnvps-nostr-domains-http".to_string()),
            namespace: Some(
                settings
                    .namespace
                    .as_deref()
                    .unwrap_or("default")
                    .to_string(),
            ),
            annotations: Some(annotations),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(ingress_spec),
        status: None,
    }
}

/// Create a single Ingress resource for all HTTPS-enabled nostr domains
fn create_unified_nostr_ingress(domains: &[NostrDomain], settings: &Settings) -> Ingress {
    let mut annotations = BTreeMap::new();

    // Add cert-manager annotations
    annotations.insert(
        "cert-manager.io/cluster-issuer".to_string(),
        settings
            .cluster_issuer
            .as_deref()
            .unwrap_or("letsencrypt-prod")
            .to_string(),
    );

    // Add configurable ingress class
    annotations.insert(
        "kubernetes.io/ingress.class".to_string(),
        settings
            .ingress_class
            .as_deref()
            .unwrap_or("nginx")
            .to_string(),
    );

    // Add default SSL redirect setting (can be overridden by custom annotations)
    annotations.insert(
        "nginx.ingress.kubernetes.io/ssl-redirect".to_string(),
        "true".to_string(),
    );

    // Add any custom annotations from configuration
    if let Some(custom_annotations) = &settings.annotations {
        for (key, value) in custom_annotations {
            annotations.insert(key.clone(), value.clone());
        }
    }

    // Collect all domain names for TLS
    let domain_names: Vec<String> = domains.iter().map(|d| d.name.clone()).collect();

    // Create TLS configuration for all domains
    let tls_config = if !domain_names.is_empty() {
        Some(vec![IngressTLS {
            hosts: Some(domain_names.clone()),
            secret_name: Some("lnvps-nostr-tls".to_string()),
        }])
    } else {
        None
    };

    // Create rules for each domain
    let rules: Vec<IngressRule> = domains
        .iter()
        .map(|domain| IngressRule {
            host: Some(domain.name.clone()),
            http: Some(k8s_openapi::api::networking::v1::HTTPIngressRuleValue {
                paths: vec![k8s_openapi::api::networking::v1::HTTPIngressPath {
                    path: Some("/".to_string()),
                    path_type: "Prefix".to_string(),
                    backend: IngressBackend {
                        service: Some(IngressServiceBackend {
                            name: settings
                                .service_name
                                .as_deref()
                                .unwrap_or("lnvps-nostr")
                                .to_string(),
                            port: Some(ServiceBackendPort {
                                number: None,
                                name: Some(
                                    settings.port_name.as_deref().unwrap_or("http").to_string(),
                                ),
                            }),
                        }),
                        resource: None,
                    },
                }],
            }),
        })
        .collect();

    let ingress_spec = IngressSpec {
        tls: tls_config,
        rules: if rules.is_empty() { None } else { Some(rules) },
        ..Default::default()
    };

    // Create labels with domain count
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "lnvps-nostr".to_string());
    labels.insert("managed-by".to_string(), "lnvps-operator".to_string());
    labels.insert("component".to_string(), "nostr-domains".to_string());
    labels.insert("domain-count".to_string(), domains.len().to_string());

    Ingress {
        metadata: ObjectMeta {
            name: Some("lnvps-nostr-domains".to_string()),
            namespace: Some(
                settings
                    .namespace
                    .as_deref()
                    .unwrap_or("default")
                    .to_string(),
            ),
            annotations: Some(annotations),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(ingress_spec),
        status: None,
    }
}

/// Reconcile nostr domain ingresses - creates separate ingresses for HTTP-only and HTTPS domains
pub async fn reconcile_nostr_domains(context: &Context) -> Result<()> {
    let ingress_api: Api<Ingress> = Api::namespaced(
        context.client.clone(),
        context.settings.namespace.as_deref().unwrap_or("default"),
    );

    info!("Fetching enabled nostr domains from database...");
    let domains = context.db.list_active_domains().await?;
    info!("Found {} enabled nostr domains", domains.len());

    // Split domains into HTTP-only and HTTPS-enabled
    let http_only_domains: Vec<&NostrDomain> = domains.iter().filter(|d| d.http_only).collect();
    let https_domains: Vec<&NostrDomain> = domains.iter().filter(|d| !d.http_only).collect();

    info!(
        "Split: {} HTTP-only domains, {} HTTPS domains",
        http_only_domains.len(),
        https_domains.len()
    );

    // Reconcile HTTP-only ingress
    reconcile_http_only_ingress(&ingress_api, &http_only_domains, &context.settings).await?;

    // Reconcile HTTPS ingress
    reconcile_https_ingress(&ingress_api, &https_domains, &context.settings).await?;

    Ok(())
}

/// Reconcile the HTTP-only ingress for pending activation domains
async fn reconcile_http_only_ingress(
    ingress_api: &Api<Ingress>,
    domains: &[&NostrDomain],
    settings: &Settings,
) -> Result<()> {
    let ingress_name = "lnvps-nostr-domains-http";

    if domains.is_empty() {
        info!("No HTTP-only domains found, checking if ingress exists to clean up...");

        // Check if ingress exists and delete it if no domains
        match ingress_api.get(ingress_name).await {
            Ok(_) => {
                info!(
                    "Deleting ingress {} as no HTTP-only domains exist",
                    ingress_name
                );
                if let Err(e) = ingress_api.delete(ingress_name, &Default::default()).await {
                    error!("Failed to delete ingress {}: {}", ingress_name, e);
                } else {
                    info!("Successfully deleted ingress {}", ingress_name);
                }
            }
            Err(kube::Error::Api(kube::core::ErrorResponse { code: 404, .. })) => {
                info!(
                    "Ingress {} does not exist, nothing to clean up",
                    ingress_name
                );
            }
            Err(e) => {
                error!("Error checking ingress {}: {}", ingress_name, e);
            }
        }
        return Ok(());
    }

    // Convert &[&NostrDomain] to Vec<NostrDomain> for create function
    let domain_vec: Vec<NostrDomain> = domains.iter().map(|d| (*d).clone()).collect();

    // Create the HTTP-only ingress
    let new_ingress = create_http_only_ingress(&domain_vec, settings);

    // Check if ingress already exists
    match ingress_api.get(ingress_name).await {
        Ok(_existing_ingress) => {
            // Ingress exists, update it
            info!(
                "Ingress {} already exists with {} HTTP-only domains configured",
                ingress_name,
                domains.len()
            );

            match ingress_api
                .replace(ingress_name, &Default::default(), &new_ingress)
                .await
            {
                Ok(_) => {
                    info!(
                        "Successfully updated ingress {} with {} HTTP-only domains",
                        ingress_name,
                        domains.len()
                    );

                    // Log the domains for debugging
                    if settings.verbose.unwrap_or(false) {
                        for domain in domains {
                            info!("  - {} (HTTP-only)", domain.name);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to update ingress {}: {}", ingress_name, e);
                }
            }
        }
        Err(kube::Error::Api(kube::core::ErrorResponse { code: 404, .. })) => {
            // Ingress doesn't exist, create it
            info!(
                "Creating ingress {} for {} HTTP-only domains",
                ingress_name,
                domains.len()
            );

            match ingress_api.create(&Default::default(), &new_ingress).await {
                Ok(_) => {
                    info!(
                        "Successfully created ingress {} with {} HTTP-only domains",
                        ingress_name,
                        domains.len()
                    );

                    // Log the domains for debugging
                    if settings.verbose.unwrap_or(false) {
                        for domain in domains {
                            info!("  - {} (HTTP-only)", domain.name);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to create ingress {}: {}", ingress_name, e);
                }
            }
        }
        Err(e) => {
            error!("Error checking ingress {}: {}", ingress_name, e);
        }
    }

    Ok(())
}

/// Reconcile the HTTPS ingress for fully activated domains
async fn reconcile_https_ingress(
    ingress_api: &Api<Ingress>,
    domains: &[&NostrDomain],
    settings: &Settings,
) -> Result<()> {
    let ingress_name = "lnvps-nostr-domains";

    if domains.is_empty() {
        info!("No HTTPS domains found, checking if ingress exists to clean up...");

        // Check if ingress exists and delete it if no domains
        match ingress_api.get(ingress_name).await {
            Ok(_) => {
                info!(
                    "Deleting ingress {} as no HTTPS domains exist",
                    ingress_name
                );
                if let Err(e) = ingress_api.delete(ingress_name, &Default::default()).await {
                    error!("Failed to delete ingress {}: {}", ingress_name, e);
                } else {
                    info!("Successfully deleted ingress {}", ingress_name);
                }
            }
            Err(kube::Error::Api(kube::core::ErrorResponse { code: 404, .. })) => {
                info!(
                    "Ingress {} does not exist, nothing to clean up",
                    ingress_name
                );
            }
            Err(e) => {
                error!("Error checking ingress {}: {}", ingress_name, e);
            }
        }
        return Ok(());
    }

    // Convert &[&NostrDomain] to Vec<NostrDomain> for create function
    let domain_vec: Vec<NostrDomain> = domains.iter().map(|d| (*d).clone()).collect();

    // Create the HTTPS ingress for all domains
    let new_ingress = create_unified_nostr_ingress(&domain_vec, settings);

    // Check if ingress already exists
    match ingress_api.get(ingress_name).await {
        Ok(_existing_ingress) => {
            // Ingress exists, check if it needs updating
            info!(
                "Ingress {} already exists with {} HTTPS domains configured",
                ingress_name,
                domains.len()
            );

            // Compare existing vs new ingress to see if update is needed
            // For now, we'll always update to ensure it's current
            match ingress_api
                .replace(ingress_name, &Default::default(), &new_ingress)
                .await
            {
                Ok(_) => {
                    info!(
                        "Successfully updated ingress {} with {} HTTPS domains",
                        ingress_name,
                        domains.len()
                    );

                    // Log the domains for debugging
                    if settings.verbose.unwrap_or(false) {
                        for domain in domains {
                            info!("  - {} (HTTPS)", domain.name);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to update ingress {}: {}", ingress_name, e);
                }
            }
        }
        Err(kube::Error::Api(kube::core::ErrorResponse { code: 404, .. })) => {
            // Ingress doesn't exist, create it
            info!(
                "Creating ingress {} for {} HTTPS domains",
                ingress_name,
                domains.len()
            );

            match ingress_api.create(&Default::default(), &new_ingress).await {
                Ok(_) => {
                    info!(
                        "Successfully created ingress {} with {} HTTPS domains",
                        ingress_name,
                        domains.len()
                    );

                    // Log the domains for debugging
                    if settings.verbose.unwrap_or(false) {
                        for domain in domains {
                            info!("  - {} (HTTPS)", domain.name);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to create ingress {}: {}", ingress_name, e);
                }
            }
        }
        Err(e) => {
            error!("Error checking ingress {}: {}", ingress_name, e);
        }
    }

    Ok(())
}
