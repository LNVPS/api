//! Shared OVH API client helpers (authentication token generation).
//!
//! OVH uses a signed-request scheme: every request carries `X-Ovh-Application`,
//! `X-Ovh-Consumer`, `X-Ovh-Timestamp` and an `X-Ovh-Signature` computed as
//! `$1$` + SHA1(`app_secret+consumer_key+METHOD+URL+BODY+TIMESTAMP`). A clock
//! delta against OVH's `/auth/time` endpoint is applied so signatures stay valid.
//!
//! Both the additional-IP "router" (`OvhDedicatedServerVMacRouter`) and the
//! reverse-DNS provider ([`crate::dns::OvhDns`]) share this code.

use crate::json_api::{JsonApi, TokenGen};
use crate::retry::{OpError, OpResult};
use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::{Method, RequestBuilder, Url};
use sha1::{Digest, Sha1};
use std::ops::Sub;

/// Generates signed OVH API request headers from an `app_key:app_secret:consumer_key` token.
#[derive(Clone)]
pub struct OvhTokenGen {
    time_delta: i64,
    application_key: String,
    application_secret: String,
    consumer_key: String,
}

impl OvhTokenGen {
    /// Parse an OVH credential token of the form `application_key:application_secret:consumer_key`.
    pub fn new(time_delta: i64, token: &str) -> Result<Self> {
        let mut t_split = token.split(":");
        Ok(Self {
            time_delta,
            application_key: t_split
                .next()
                .context("Missing application_key")?
                .to_string(),
            application_secret: t_split
                .next()
                .context("Missing application_secret")?
                .to_string(),
            consumer_key: t_split.next().context("Missing consumer_key")?.to_string(),
        })
    }

    /// Compute signature for OVH.
    fn build_sig(
        method: &str,
        query: &str,
        body: &str,
        timestamp: &str,
        aas: &str,
        ck: &str,
    ) -> String {
        let sep = "+";
        let prefix = "$1$".to_string();

        let capacity = 1
            + aas.len()
            + sep.len()
            + ck.len()
            + method.len()
            + sep.len()
            + query.len()
            + sep.len()
            + body.len()
            + sep.len()
            + timestamp.len();
        let mut signature = String::with_capacity(capacity);
        signature.push_str(aas);
        signature.push_str(sep);
        signature.push_str(ck);
        signature.push_str(sep);
        signature.push_str(method);
        signature.push_str(sep);
        signature.push_str(query);
        signature.push_str(sep);
        signature.push_str(body);
        signature.push_str(sep);
        signature.push_str(timestamp);

        let mut hasher = Sha1::new();
        hasher.update(signature.as_bytes());
        let sig = hex::encode(hasher.finalize());
        prefix + &sig
    }
}

impl TokenGen for OvhTokenGen {
    fn generate_token(
        &self,
        method: Method,
        url: &Url,
        body: Option<&str>,
        req: RequestBuilder,
    ) -> Result<RequestBuilder> {
        let now = Utc::now().timestamp().sub(self.time_delta);
        let now_string = now.to_string();
        let sig = Self::build_sig(
            method.as_str(),
            url.as_str(),
            body.unwrap_or(""),
            now_string.as_str(),
            &self.application_secret,
            &self.consumer_key,
        );
        Ok(req
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("X-Ovh-Timestamp", now_string)
            .header("X-Ovh-Signature", sig))
    }
}

/// Build a [`JsonApi`] authenticated with OVH signed requests, bootstrapping the
/// clock delta from OVH's `/auth/time` endpoint.
pub async fn ovh_json_api(url: &str, token: &str) -> OpResult<JsonApi> {
    let time_api = JsonApi::new(url).map_err(OpError::Fatal)?;
    let time = time_api.get::<i64>("v1/auth/time").await?;
    let delta: i64 = Utc::now().timestamp().sub(time);

    JsonApi::token_gen(
        url,
        false,
        OvhTokenGen::new(delta, token).map_err(OpError::Fatal)?,
    )
    .map_err(OpError::Fatal)
}
