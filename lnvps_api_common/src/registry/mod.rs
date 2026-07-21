//! LIR registry object management (route/route6 IRR objects + RPKI ROAs).
//!
//! Fulfilment of an IP-range / ASN-sponsoring subscription does **not** involve
//! announcing the space ourselves — it means creating the registry-side objects
//! so the customer can announce it:
//!
//! * an IRR `route` / `route6` object (created in the RIR whois database, e.g.
//!   RIPE) authorising the customer's origin ASN to originate the prefix, via
//!   [`RegistryProvider`]; and
//! * an RPKI ROA authorising the same (prefix, origin-AS, max-length), via
//!   [`RpkiProvider`].
//!
//! These are two separate provider traits because they are fulfilled by
//! different systems: the IRR object goes to the RIR whois REST API
//! ([`ripe::RipeDb`]) while ROAs are issued from our own **delegated** RPKI CA
//! ([`krill::Krill`]) so we can sign ROAs for sponsored / sub-allocated space
//! that RIPE's LIR-only hosted RPKI API cannot cover.

mod krill;
mod ripe;

pub use krill::*;
pub use ripe::*;

use crate::retry::OpResult;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// An IRR `route` (IPv4) / `route6` (IPv6) object to be created in the RIR
/// whois database. Identifies the customer prefix and the ASN permitted to
/// originate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteObject {
    /// The customer prefix, e.g. `193.0.0.0/24` or `2001:db8::/48`.
    pub prefix: IpNetwork,
    /// The origin AS number (bare, without the `AS` prefix), e.g. `3333`.
    pub origin_asn: u32,
    /// Free-form `descr:` attribute value.
    pub description: String,
    /// The `mnt-by:` maintainer that will own the created object.
    pub maintainer: String,
}

impl RouteObject {
    /// The whois object type for this prefix family (`route` or `route6`).
    pub fn object_type(&self) -> &'static str {
        match self.prefix {
            IpNetwork::V4(_) => "route",
            IpNetwork::V6(_) => "route6",
        }
    }

    /// The origin formatted for whois/RPKI, e.g. `AS3333`.
    pub fn origin(&self) -> String {
        format!("AS{}", self.origin_asn)
    }

    /// The whois primary key used to address the object in REST paths, formed
    /// by concatenating the prefix and origin, e.g. `193.0.0.0/24AS3333`.
    pub fn primary_key(&self) -> String {
        format!("{}{}", self.prefix, self.origin())
    }
}

/// A provider-assigned reference to a created registry object. For the RIR
/// whois database this is the object's primary key (prefix + origin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryRef(pub String);

impl Display for RegistryRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Manages IRR `route`/`route6` objects in a Regional Internet Registry.
#[async_trait]
pub trait RegistryProvider: Send + Sync {
    /// Create a `route`/`route6` object; returns its stable reference.
    async fn create_route_object(&self, obj: &RouteObject) -> OpResult<RegistryRef>;

    /// Delete a previously created `route`/`route6` object.
    async fn delete_route_object(&self, obj: &RouteObject) -> OpResult<()>;
}

/// A single RPKI Route Origin Authorisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoaDefinition {
    /// The authorised origin AS number (bare), e.g. `3333`.
    pub origin_asn: u32,
    /// The authorised prefix, e.g. `193.0.0.0/24`.
    pub prefix: IpNetwork,
    /// The maximum announced prefix length. `None` pins it to the prefix's own
    /// length (i.e. no more-specifics permitted).
    pub max_length: Option<u8>,
}

impl RoaDefinition {
    /// Effective max length: the explicit value or the prefix's own length.
    pub fn effective_max_length(&self) -> u8 {
        self.max_length.unwrap_or_else(|| self.prefix.prefix())
    }
}

/// Issues/withdraws RPKI ROAs from a delegated RPKI CA.
#[async_trait]
pub trait RpkiProvider: Send + Sync {
    /// Publish a ROA authorising `(prefix, origin, max_length)`.
    async fn add_roa(&self, roa: &RoaDefinition) -> OpResult<()>;

    /// Withdraw a previously published ROA.
    async fn remove_roa(&self, roa: &RoaDefinition) -> OpResult<()>;

    /// List all currently published ROAs for the CA.
    async fn list_roas(&self) -> OpResult<Vec<RoaDefinition>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4() -> RouteObject {
        RouteObject {
            prefix: "193.0.0.0/24".parse().unwrap(),
            origin_asn: 3333,
            description: "LNVPS customer".to_string(),
            maintainer: "LNVPS-MNT".to_string(),
        }
    }

    #[test]
    fn test_route_object_v4_shape() {
        let o = v4();
        assert_eq!(o.object_type(), "route");
        assert_eq!(o.origin(), "AS3333");
        assert_eq!(o.primary_key(), "193.0.0.0/24AS3333");
    }

    #[test]
    fn test_route_object_v6_type() {
        let o = RouteObject {
            prefix: "2001:db8::/48".parse().unwrap(),
            ..v4()
        };
        assert_eq!(o.object_type(), "route6");
        assert_eq!(o.primary_key(), "2001:db8::/48AS3333");
    }

    #[test]
    fn test_registry_ref_display() {
        assert_eq!(RegistryRef("x/24AS1".into()).to_string(), "x/24AS1");
    }

    #[test]
    fn test_roa_effective_max_length() {
        let mut r = RoaDefinition {
            origin_asn: 3333,
            prefix: "193.0.0.0/24".parse().unwrap(),
            max_length: None,
        };
        // Falls back to the prefix length.
        assert_eq!(r.effective_max_length(), 24);
        r.max_length = Some(28);
        assert_eq!(r.effective_max_length(), 28);
    }
}
