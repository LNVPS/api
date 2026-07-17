//! Minimal software WebAuthn authenticator for e2e passkey tests.
//!
//! The server drives **usernameless / discoverable** login
//! (`start_discoverable_authentication`), which requires the authenticator to
//! store a *resident* credential and return its `userHandle` on assertion. The
//! `webauthn-authenticator-rs` `SoftPasskey` explicitly does not support
//! resident keys and returns no `userHandle`, so it can't exercise this flow.
//!
//! This is a small, purpose-built authenticator that:
//! - generates an ES256 (P-256) credential on registration,
//! - stores it as a resident credential keyed by RP id + userHandle,
//! - produces `webauthn.get` assertions (with `userHandle`) for discoverable
//!   authentication.
//!
//! It uses the exact `webauthn-rs-proto` types the API serialises, so there is
//! no JSON-shape guesswork.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw,
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

/// A stored resident credential.
struct ResidentCredential {
    rp_id: String,
    cred_id: Vec<u8>,
    signing_key: SigningKey,
    user_handle: Vec<u8>,
}

/// A software authenticator that supports discoverable (resident-key) passkeys.
///
/// One instance models a single physical authenticator; it can hold several
/// resident credentials.
pub struct SoftAuthenticator {
    /// The origin this authenticator reports in `clientDataJSON`. Must match the
    /// server's configured `rp_origin`.
    origin: String,
    credentials: Vec<ResidentCredential>,
}

impl SoftAuthenticator {
    /// Create an authenticator that reports `origin` (e.g. `http://localhost:8000`).
    pub fn new(origin: &str) -> Self {
        Self {
            origin: origin.trim_end_matches('/').to_string(),
            credentials: Vec::new(),
        }
    }

    /// Perform a registration ceremony (`navigator.credentials.create`).
    ///
    /// Consumes the server's challenge and returns the credential to POST to the
    /// `.../finish` endpoint. The resident credential is stored so later
    /// discoverable logins can use it.
    pub fn register(
        &mut self,
        ccr: &CreationChallengeResponse,
    ) -> Result<RegisterPublicKeyCredential> {
        let opts = &ccr.public_key;
        let rp_id = opts.rp.id.clone();
        let challenge = opts.challenge.as_ref().to_vec();
        let user_handle = opts.user.id.as_ref().to_vec();

        // Fresh ES256 credential key.
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let ep = verifying_key.to_encoded_point(false);
        let x = ep.x().context("missing EC x coord")?;
        let y = ep.y().context("missing EC y coord")?;

        // Random 32-byte credential id.
        let mut cred_id = vec![0u8; 32];
        OsRng.fill_bytes(&mut cred_id);

        let cose_key = cose_es256_key(x.as_slice(), y.as_slice());

        // authenticatorData: rpIdHash || flags || counter || attestedCredentialData
        let rp_id_hash = sha256(rp_id.as_bytes());
        // UP (0x01) | UV (0x04) | AT (0x40)
        let flags = 0b0100_0101u8;
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // sign counter
        // attestedCredentialData
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID (zeroed)
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&cred_id);
        auth_data.extend_from_slice(&cose_key);

        // attestationObject: { fmt: "none", attStmt: {}, authData: <bytes> }
        let attestation_object = cbor_attestation_none(&auth_data);

        let client_data_json = client_data_json("webauthn.create", &challenge, &self.origin);

        self.credentials.push(ResidentCredential {
            rp_id,
            cred_id: cred_id.clone(),
            signing_key,
            user_handle,
        });

        Ok(RegisterPublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(&cred_id),
            raw_id: cred_id.into(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: attestation_object.into(),
                client_data_json: client_data_json.into_bytes().into(),
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        })
    }

    /// Perform a discoverable authentication ceremony
    /// (`navigator.credentials.get` with an empty `allowCredentials`).
    ///
    /// Picks a matching resident credential for the RP, signs the assertion and
    /// returns the credential (including `userHandle`) to POST to the
    /// `.../login/finish` endpoint.
    pub fn authenticate(&self, rcr: &RequestChallengeResponse) -> Result<PublicKeyCredential> {
        let opts = &rcr.public_key;
        let rp_id = &opts.rp_id;
        let challenge = opts.challenge.as_ref().to_vec();

        let cred = self
            .credentials
            .iter()
            .find(|c| &c.rp_id == rp_id)
            .context("no resident credential for this RP")?;

        let rp_id_hash = sha256(rp_id.as_bytes());
        // UP (0x01) | UV (0x04)
        let flags = 0b0000_0101u8;
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // sign counter

        let client_data_json = client_data_json("webauthn.get", &challenge, &self.origin);
        let client_data_hash = sha256(client_data_json.as_bytes());

        // Signature over authenticatorData || SHA256(clientDataJSON), ES256 (DER).
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let sig: Signature = cred.signing_key.sign(&signed);
        let der = sig.to_der();

        Ok(PublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(&cred.cred_id),
            raw_id: cred.cred_id.clone().into(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: auth_data.into(),
                client_data_json: client_data_json.into_bytes().into(),
                signature: der.as_bytes().to_vec().into(),
                user_handle: Some(cred.user_handle.clone().into()),
            },
            extensions: Default::default(),
            type_: "public-key".to_string(),
        })
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Build the `clientDataJSON` for a ceremony. Field order matches what browsers
/// emit; the server parses it as JSON so order is not significant.
fn client_data_json(ceremony_type: &str, challenge: &[u8], origin: &str) -> String {
    // serde_json handles escaping; keys are fixed and simple.
    serde_json::json!({
        "type": ceremony_type,
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
}

// --- Minimal CBOR encoding (only what attestation/COSE need) ---

/// CBOR head byte(s) for a given major type and argument value.
fn cbor_head(major: u8, val: u64) -> Vec<u8> {
    let mt = major << 5;
    if val < 24 {
        vec![mt | val as u8]
    } else if val < 0x100 {
        vec![mt | 24, val as u8]
    } else if val < 0x1_0000 {
        let b = (val as u16).to_be_bytes();
        vec![mt | 25, b[0], b[1]]
    } else {
        let b = (val as u32).to_be_bytes();
        vec![mt | 26, b[0], b[1], b[2], b[3]]
    }
}

fn cbor_uint(v: u64) -> Vec<u8> {
    cbor_head(0, v)
}

/// Encode a negative integer (major type 1). `v` must be negative.
fn cbor_nint(v: i64) -> Vec<u8> {
    debug_assert!(v < 0);
    cbor_head(1, (-1 - v) as u64)
}

fn cbor_bstr(bytes: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

fn cbor_tstr(s: &str) -> Vec<u8> {
    let mut out = cbor_head(3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

/// COSE_Key for an ES256 (P-256) public key.
fn cose_es256_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(5, 5); // map with 5 entries
    out.extend(cbor_uint(1)); // kty
    out.extend(cbor_uint(2)); //   EC2
    out.extend(cbor_uint(3)); // alg
    out.extend(cbor_nint(-7)); //   ES256
    out.extend(cbor_nint(-1)); // crv
    out.extend(cbor_uint(1)); //   P-256
    out.extend(cbor_nint(-2)); // x
    out.extend(cbor_bstr(x));
    out.extend(cbor_nint(-3)); // y
    out.extend(cbor_bstr(y));
    out
}

/// Attestation object with `fmt: "none"` and an empty statement.
fn cbor_attestation_none(auth_data: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(5, 3); // map with 3 entries
    out.extend(cbor_tstr("fmt"));
    out.extend(cbor_tstr("none"));
    out.extend(cbor_tstr("attStmt"));
    out.extend(cbor_head(5, 0)); // empty map
    out.extend(cbor_tstr("authData"));
    out.extend(cbor_bstr(auth_data));
    out
}

#[cfg(test)]
mod tests {
    use super::SoftAuthenticator;
    use std::time::Duration;
    use webauthn_rs::prelude::{DiscoverableKey, Passkey, Url, Webauthn, WebauthnBuilder};
    use webauthn_rs_core::WebauthnCore;
    use webauthn_rs_core::proto::{
        AttestationConveyancePreference, COSEAlgorithm, UserVerificationPolicy,
    };

    const RP_ID: &str = "localhost";
    const ORIGIN: &str = "http://localhost:8000";

    /// Register a discoverable credential (mirroring the server's core path),
    /// then complete a usernameless discoverable authentication with it. This
    /// validates the authenticator's attestation/COSE/assertion bytes offline,
    /// without needing the live API.
    #[test]
    fn soft_authenticator_discoverable_roundtrip() {
        let origin = Url::parse(ORIGIN).unwrap();
        let core = WebauthnCore::new_unsafe_experts_only(
            "LNVPS test",
            RP_ID,
            vec![origin.clone()],
            Duration::from_secs(60),
            None,
            None,
        );

        // --- Registration, as the server does (resident key, UV required) ---
        let builder = core
            .new_challenge_register_builder(&[9u8; 16], "alice", "alice")
            .unwrap()
            .attestation(AttestationConveyancePreference::None)
            .credential_algorithms(COSEAlgorithm::secure_algs())
            .require_resident_key(true)
            .authenticator_attachment(None)
            .user_verification_policy(UserVerificationPolicy::Required)
            .reject_synchronised_authenticators(false)
            .exclude_credentials(None)
            .hints(None)
            .extensions(None);
        let (ccr, reg_state) = core.generate_challenge_register(builder).unwrap();

        let mut authenticator = SoftAuthenticator::new(ORIGIN);
        let reg_cred = authenticator.register(&ccr).expect("register");

        let credential = core
            .register_credential(&reg_cred, &reg_state, None)
            .expect("server accepts registration");
        let passkey = Passkey::from(credential);

        // --- Usernameless (discoverable) authentication ---
        let webauthn: Webauthn = WebauthnBuilder::new(RP_ID, &origin)
            .unwrap()
            .rp_name("LNVPS test")
            .build()
            .unwrap();

        let (rcr, auth_state) = webauthn.start_discoverable_authentication().unwrap();
        let assertion = authenticator.authenticate(&rcr).expect("authenticate");

        // The server identifies the account by the returned credential id, then
        // verifies against the stored passkey(s).
        let (_uuid, _cred_id) = webauthn
            .identify_discoverable_authentication(&assertion)
            .expect("identify");
        let discoverable = [DiscoverableKey::from(&passkey)];
        webauthn
            .finish_discoverable_authentication(&assertion, auth_state, &discoverable)
            .expect("server accepts assertion");
    }
}
