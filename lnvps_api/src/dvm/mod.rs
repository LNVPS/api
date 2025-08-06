mod lnvps;

use crate::dvm::lnvps::LnvpsDvm;
use crate::provisioner::LNVpsProvisioner;
use anyhow::Result;
use futures::FutureExt;
use log::{error, info, warn};
use nostr::Filter;
use nostr_sdk::prelude::DataVendingMachineStatus;
use nostr_sdk::{
    Client, Event, EventBuilder, EventId, Kind, RelayPoolNotification, Tag, Timestamp, Url,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct DVMJobRequest {
    /// The source event
    pub event: Event,
    /// Input data for the job (zero or more inputs)
    pub inputs: Vec<DVMInput>,
    /// Expected output format. Different job request kind defines this more precisely.
    pub output_type: Option<String>,
    /// Optional parameters for the job as key (first argument)/value (second argument).
    /// Different job request kind defines this more precisely. (e.g. [ "param", "lang", "es" ])
    pub params: HashMap<String, String>,
    /// Customer MAY specify a maximum amount (in millisats) they are willing to pay
    pub bid: Option<u64>,
    /// List of relays where Service Providers SHOULD publish responses to
    pub relays: Vec<String>,
}

#[derive(Clone)]
pub enum DVMInput {
    Url {
        url: Url,
        relay: Option<String>,
        marker: Option<String>,
    },
    Event {
        event: EventId,
        relay: Option<String>,
        marker: Option<String>,
    },
    Job {
        event: EventId,
        relay: Option<String>,
        marker: Option<String>,
    },
    Text {
        data: String,
        relay: Option<String>,
        marker: Option<String>,
    },
}

/// Basic DVM handler that accepts a job request
pub trait DVMHandler: Send + Sync {
    fn handle_request(
        &mut self,
        request: DVMJobRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;
}

pub(crate) fn build_status_for_job(
    req: &DVMJobRequest,
    status: DataVendingMachineStatus,
    extra: Option<&str>,
    content: Option<&str>,
) -> EventBuilder {
    EventBuilder::new(Kind::JobFeedback, content.unwrap_or("")).tags([
        Tag::parse(["status", status.to_string().as_str(), extra.unwrap_or("")]).unwrap(),
        Tag::expiration(Timestamp::now() + Duration::from_secs(30)),
        Tag::event(req.event.id),
        Tag::public_key(req.event.pubkey),
    ])
}

/// Start listening for jobs with a specific handler
fn listen_for_jobs(
    client: Client,
    kind: Kind,
    mut dvm: Box<dyn DVMHandler>,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
    Box::pin(async move {
        let sub = client
            .subscribe(Filter::new().kind(kind).since(Timestamp::now()), None)
            .await?;

        info!("Listening for jobs: {}", kind);
        let mut rx = client.notifications();
        while let Ok(e) = rx.recv().await {
            match e {
                RelayPoolNotification::Event { event, .. } if event.kind == kind => {
                    match parse_job_request(&event) {
                        Ok(req) => {
                            if let Err(e) = dvm.handle_request(req.clone()).await {
                                error!("Error handling job request: {}", e);

                                let data = build_status_for_job(
                                    &req,
                                    DataVendingMachineStatus::Error,
                                    Some(e.to_string().as_str()),
                                    None,
                                );
                                client.send_event_builder(data).await?;
                            }
                        }
                        Err(e) => warn!("Invalid job request: {:?}", e),
                    }
                }
                _ => {}
            }
        }

        client.unsubscribe(&sub).await;
        Ok(())
    })
}

fn parse_job_request(event: &Event) -> Result<DVMJobRequest> {
    let mut inputs = vec![];
    for i_tag in event
        .tags
        .iter()
        .filter(|t| t.kind().as_str() == "i")
        .map(|t| t.as_slice())
    {
        let input = match i_tag[2].as_str() {
            "url" => DVMInput::Url {
                url: if let Ok(u) = i_tag[1].parse() {
                    u
                } else {
                    warn!("Invalid url: {}", i_tag[1]);
                    continue;
                },
                relay: if i_tag.len() > 3 {
                    Some(i_tag[3].to_string())
                } else {
                    None
                },
                marker: if i_tag.len() > 4 {
                    Some(i_tag[4].to_string())
                } else {
                    None
                },
            },
            "event" => DVMInput::Event {
                event: if let Ok(t) = EventId::parse(&i_tag[1]) {
                    t
                } else {
                    warn!("Invalid event id: {}", i_tag[1]);
                    continue;
                },
                relay: if i_tag.len() > 3 {
                    Some(i_tag[3].to_string())
                } else {
                    None
                },
                marker: if i_tag.len() > 4 {
                    Some(i_tag[4].to_string())
                } else {
                    None
                },
            },
            "job" => DVMInput::Job {
                event: if let Ok(t) = EventId::parse(&i_tag[1]) {
                    t
                } else {
                    warn!("Invalid event id in job: {}", i_tag[1]);
                    continue;
                },
                relay: if i_tag.len() > 3 {
                    Some(i_tag[3].to_string())
                } else {
                    None
                },
                marker: if i_tag.len() > 4 {
                    Some(i_tag[4].to_string())
                } else {
                    None
                },
            },
            "text" => DVMInput::Text {
                data: i_tag[1].to_string(),
                relay: if i_tag.len() > 3 {
                    Some(i_tag[3].to_string())
                } else {
                    None
                },
                marker: if i_tag.len() > 4 {
                    Some(i_tag[4].to_string())
                } else {
                    None
                },
            },
            t => {
                warn!("unknown tag: {}", t);
                continue;
            }
        };
        inputs.push(input);
    }

    let params: HashMap<String, String> = event
        .tags
        .iter()
        .filter(|t| t.kind().as_str() == "param")
        .filter_map(|p| {
            let p = p.as_slice();
            if p.len() == 3 {
                Some((p[1].clone(), p[2].clone()))
            } else {
                warn!("Invalid param: {}", p.join(", "));
                None
            }
        })
        .collect();
    Ok(DVMJobRequest {
        event: event.clone(),
        inputs,
        output_type: event
            .tags
            .iter()
            .find(|t| t.kind().as_str() == "output")
            .and_then(|t| t.content())
            .map(|s| s.to_string()),
        params,
        bid: event
            .tags
            .iter()
            .find(|t| t.kind().as_str() == "bid")
            .and_then(|t| t.content())
            .and_then(|t| t.parse::<u64>().ok()),
        relays: event
            .tags
            .iter()
            .filter(|t| t.kind().as_str() == "relay")
            .flat_map(|c| &c.as_slice()[1..])
            .map(|s| s.to_string())
            .collect(),
    })
}

pub fn start_dvms(client: Client, provisioner: Arc<LNVpsProvisioner>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let dvm = LnvpsDvm::new(provisioner, client.clone());
        if let Err(e) = listen_for_jobs(client, Kind::from_u16(5999), Box::new(dvm)).await {
            error!("Error listening jobs: {}", e);
        }
    })
}
