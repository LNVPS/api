use crate::comma_separated::CommaSeparated;
use crate::encrypted_string::EncryptedString;
use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::str::FromStr;
use url::Url;

/// How a user authenticates / what their `pubkey` represents.
#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum AccountType {
    /// Native Nostr account. `pubkey` is a real 32-byte schnorr x-only public
    /// key and can be used for NIP-17 DMs, npub display, event signing, etc.
    #[default]
    Nostr = 0,
    /// External OAuth/OIDC account. `pubkey` is a synthetic
    /// `sha256("{provider}:{subject}")` identifier used only as an opaque
    /// primary identity — it is NOT a real Nostr key and must never be treated
    /// as one (no NIP-17, no npub, no signing).
    OAuth = 1,
    /// Passwordless WebAuthn / passkey account. `pubkey` is a synthetic
    /// `sha256("webauthn:{user_handle}")` identifier derived from the
    /// credential's user handle — like [`AccountType::OAuth`] it is NOT a real
    /// Nostr key. The account's login factors live in `user_webauthn_credentials`.
    Webauthn = 2,
}

impl Display for AccountType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountType::Nostr => write!(f, "nostr"),
            AccountType::OAuth => write!(f, "oauth"),
            AccountType::Webauthn => write!(f, "webauthn"),
        }
    }
}

#[derive(FromRow, Clone, Debug, Default)]
/// Users who buy VM's
pub struct User {
    /// Unique ID of this user (database generated)
    pub id: u64,
    /// The nostr public key for this user (or a synthetic identifier for
    /// non-Nostr accounts — see [`User::account_type`]).
    pub pubkey: Vec<u8>,
    /// Whether this user is a native Nostr account or an external OAuth account.
    /// Determines whether `pubkey` is a usable Nostr key.
    #[sqlx(default)]
    pub account_type: AccountType,
    /// When this user first started using the service (first login)
    pub created: DateTime<Utc>,
    /// Users email address for notifications (encrypted)
    pub email: EncryptedString,
    /// SHA-256 hash of lowercased+trimmed email for lookups (32 bytes)
    pub email_hash: Option<Vec<u8>>,
    /// Whether the email address has been verified
    pub email_verified: bool,
    /// Token used for email address verification (empty string means no pending verification)
    pub email_verify_token: String,
    /// If user should be contacted via NIP-17 for notifications
    pub contact_nip17: bool,
    /// If user should be contacted via email for notifications
    pub contact_email: bool,
    /// If user should be contacted via Telegram for notifications
    pub contact_telegram: bool,
    /// Telegram chat id to deliver messages to (set once the account is linked)
    pub telegram_chat_id: Option<i64>,
    /// One-time token used to link a Telegram chat to this account.
    /// Empty/`None` once linking has completed.
    pub telegram_link_token: Option<String>,
    /// If user should be contacted via WhatsApp for notifications
    pub contact_whatsapp: bool,
    /// WhatsApp phone number in E.164 format (e.g. `+15551234567`)
    pub whatsapp_number: Option<String>,
    /// Whether the WhatsApp number has been verified
    pub whatsapp_verified: bool,
    /// Pending one-time verification code sent to the WhatsApp number.
    /// `None` once verification has completed.
    pub whatsapp_verify_code: Option<String>,
    /// Users country
    pub country_code: Option<String>,
    /// Name to show on invoices
    pub billing_name: Option<String>,
    /// Billing address line 1
    pub billing_address_1: Option<String>,
    /// Billing address line 2
    pub billing_address_2: Option<String>,
    /// Billing city
    pub billing_city: Option<String>,
    /// Billing state/county
    pub billing_state: Option<String>,
    /// Billing postcode/zip
    pub billing_postcode: Option<String>,
    /// Billing tax id
    pub billing_tax_id: Option<String>,
    /// Country (ISO 3166-1 alpha-3) resolved from the client's IP address.
    ///
    /// This is an *independent* place-of-supply evidence signal for EU VAT,
    /// captured automatically and stored separately from the self-declared
    /// `country_code` so the two can be compared / conflicts flagged.
    #[sqlx(default)]
    pub geo_country_code: Option<String>,
    /// Last client IP address geolocation was resolved from.
    #[sqlx(default)]
    pub geo_ip: Option<String>,
    /// When the geolocation was last resolved.
    #[sqlx(default)]
    pub geo_updated: Option<DateTime<Utc>>,
}

/// A saved payment method for off-session (merchant-initiated) automatic
/// renewals. Provider-agnostic. Stores only opaque provider token references
/// (encrypted) plus non-sensitive card metadata (brand/last4/expiry) — never
/// card PAN/CVV.
#[derive(FromRow, Clone, Debug, Default)]
pub struct UserPaymentMethod {
    pub id: u64,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    /// Payment processor (e.g. `revolut`)
    pub provider: String,
    /// Optional user-defined label to distinguish multiple methods
    pub name: Option<String>,
    /// Encrypted provider customer id owning the saved method (None for
    /// providers without one, e.g. NWC)
    pub external_customer_id: Option<EncryptedString>,
    /// Encrypted reusable payment method id charged off-session
    pub external_id: EncryptedString,
    pub card_brand: Option<String>,
    pub card_last_four: Option<String>,
    pub exp_month: Option<u16>,
    pub exp_year: Option<u16>,
    /// Default method for this provider
    pub is_default: bool,
    /// Whether this method is usable (disabled when expired/revoked)
    pub enabled: bool,
}

impl UserPaymentMethod {
    /// Whether the card has expired as of the given year/month (1-based month).
    /// Methods without expiry data are treated as non-expiring.
    pub fn is_expired(&self, year: u16, month: u16) -> bool {
        match (self.exp_year, self.exp_month) {
            (Some(ey), Some(em)) => (ey, em) < (year, month),
            _ => false,
        }
    }
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct UserSshKey {
    pub id: u64,
    pub name: String,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    pub key_data: EncryptedString,
}

/// A registered WebAuthn / passkey credential belonging to a
/// [`AccountType::Webauthn`] account. One account may have several (e.g. one
/// per device).
#[derive(FromRow, Clone, Debug, Default)]
pub struct WebauthnCredential {
    pub id: u64,
    /// Owning user id.
    pub user_id: u64,
    /// Raw credential id bytes (unique across all accounts).
    pub cred_id: Vec<u8>,
    /// JSON-serialised `webauthn_rs::prelude::Passkey`. This is the source of
    /// truth for the credential's public key and signature counter; it is
    /// re-serialised after each successful authentication.
    pub passkey: String,
    /// Optional user-facing label for the credential/device.
    pub name: Option<String>,
    pub created: DateTime<Utc>,
    /// When the credential was last used to authenticate.
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct AdminUserInfo {
    #[sqlx(flatten)]
    pub user_info: User,
    // Admin-specific fields
    pub vm_count: i64,
    pub is_admin: bool,
    /// Whether the user has an NWC payment method configured (computed)
    pub has_nwc: bool,
}

#[derive(Clone, Debug, sqlx::Type, Default, PartialEq, Eq)]
#[repr(u16)]
/// The type of VM host
pub enum VmHostKind {
    #[default]
    Proxmox = 0,
    LibVirt = 1,

    Dummy = u16::MAX,
}

impl Display for VmHostKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VmHostKind::Proxmox => write!(f, "proxmox"),
            VmHostKind::LibVirt => write!(f, "libvirt"),
            VmHostKind::Dummy => write!(f, "dummy"),
        }
    }
}

/// CPU manufacturer
#[derive(Clone, Debug, sqlx::Type, PartialEq, Eq, Default, Copy)]
#[repr(u16)]
pub enum CpuMfg {
    #[default]
    Unknown = 0,
    Intel = 1,
    Amd = 2,
    Apple = 3,
    Nvidia = 4,
    Arm = 5,
}

impl Display for CpuMfg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CpuMfg::Unknown => write!(f, "unknown"),
            CpuMfg::Intel => write!(f, "intel"),
            CpuMfg::Amd => write!(f, "amd"),
            CpuMfg::Apple => write!(f, "apple"),
            CpuMfg::Nvidia => write!(f, "nvidia"),
            CpuMfg::Arm => write!(f, "arm"),
        }
    }
}

impl std::str::FromStr for CpuMfg {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "intel" => Ok(CpuMfg::Intel),
            "amd" => Ok(CpuMfg::Amd),
            "apple" => Ok(CpuMfg::Apple),
            "nvidia" => Ok(CpuMfg::Nvidia),
            "arm" => Ok(CpuMfg::Arm),
            "unknown" => Ok(CpuMfg::Unknown),
            _ => Err(()),
        }
    }
}

/// CPU architecture
#[derive(Clone, Debug, sqlx::Type, PartialEq, Eq, Default, Copy)]
#[repr(u16)]
pub enum CpuArch {
    #[default]
    Unknown = 0,
    X86_64 = 1,
    ARM64 = 2,
}

impl Display for CpuArch {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CpuArch::Unknown => write!(f, "unknown"),
            CpuArch::X86_64 => write!(f, "x86_64"),
            CpuArch::ARM64 => write!(f, "arm64"),
        }
    }
}

impl std::str::FromStr for CpuArch {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "x86_64" | "x86-64" | "amd64" => Ok(CpuArch::X86_64),
            "arm64" | "aarch64" => Ok(CpuArch::ARM64),
            "unknown" => Ok(CpuArch::Unknown),
            _ => Err(()),
        }
    }
}

/// CPU feature flags relevant for workload capability
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CpuFeature {
    // ── SIMD instruction sets (x86) ──────────────────────────────────────────
    SSE,
    SSE2,
    SSE3,
    SSSE3,
    SSE4_1,
    SSE4_2,
    AVX,
    AVX2,
    /// Fused Multiply-Add (FMA3)
    FMA,
    /// Half-precision floating point conversion
    F16C,
    /// AVX-512 Foundation
    AVX512F,
    /// AVX-512 Vector Neural Network Instructions (ML inference)
    AVX512VNNI,
    /// AVX-512 BFloat16 (ML training/inference)
    AVX512BF16,
    /// AVX-VNNI (VEX-encoded, non-AVX-512) - Alder Lake+
    AVXVNNI,

    // ── SIMD instruction sets (ARM) ──────────────────────────────────────────
    /// ARM NEON SIMD
    NEON,
    /// ARM Scalable Vector Extension
    SVE,
    /// ARM SVE2
    SVE2,

    // ── Cryptographic acceleration ───────────────────────────────────────────
    /// AES-NI (x86) / AES (ARM)
    AES,
    /// SHA extensions (SHA-1, SHA-256)
    SHA,
    /// SHA-512 extensions
    SHA512,
    /// Polynomial multiplication for GCM/CRC (x86 PCLMULQDQ / ARM PMULL)
    PCLMULQDQ,
    /// Hardware random number generation (RDRAND/RDSEED, ARM RNDR)
    RNG,
    /// Galois Field New Instructions (crypto, compression)
    GFNI,
    /// Vector AES (AVX-512 / AVX)
    VAES,
    /// Vector PCLMULQDQ (AVX-512 / AVX)
    VPCLMULQDQ,

    // ── Virtualization (CPU features) ────────────────────────────────────────
    /// Hardware virtualization (Intel VT-x / AMD-V / ARM VHE)
    VMX,
    /// Nested virtualization support
    NestedVirt,

    // ── AI/ML acceleration (CPU integrated) ──────────────────────────────────
    /// Intel AMX (Advanced Matrix Extensions) - Sapphire Rapids+
    AMX,
    /// ARM SME (Scalable Matrix Extension)
    SME,

    // ── Confidential computing (CPU features) ────────────────────────────────
    /// Intel SGX (Software Guard Extensions)
    SGX,
    /// AMD SEV (Secure Encrypted Virtualization)
    SEV,
    /// Intel TDX (Trust Domain Extensions)
    TDX,

    // ── Hardware video encode (iGPU: Intel QSV, AMD VCN / dGPU: NVENC, AMF) ──
    /// H.264/AVC hardware encode
    EncodeH264,
    /// H.265/HEVC hardware encode
    EncodeHEVC,
    /// AV1 hardware encode
    EncodeAV1,
    /// VP9 hardware encode
    EncodeVP9,
    /// JPEG hardware encode
    EncodeJPEG,

    // ── Hardware video decode (iGPU: Intel QSV, AMD VCN / dGPU: NVDEC, AMF) ──
    /// H.264/AVC hardware decode
    DecodeH264,
    /// H.265/HEVC hardware decode
    DecodeHEVC,
    /// AV1 hardware decode
    DecodeAV1,
    /// VP9 hardware decode
    DecodeVP9,
    /// JPEG hardware decode
    DecodeJPEG,
    /// MPEG-2 hardware decode
    DecodeMPEG2,
    /// VC-1 hardware decode
    DecodeVC1,

    // ── Video processing ─────────────────────────────────────────────────────
    /// Hardware video scaling/resize
    VideoScaling,
    /// Hardware deinterlacing
    VideoDeinterlace,
    /// Hardware color space conversion
    VideoCSC,
    /// Hardware video composition/overlay
    VideoComposition,
}

/// Discrete GPU manufacturer
#[derive(Clone, Debug, sqlx::Type, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum GpuMfg {
    #[default]
    None,
    Nvidia,
    Amd,
}

impl Display for GpuMfg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuMfg::None => write!(f, "none"),
            GpuMfg::Nvidia => write!(f, "nvidia"),
            GpuMfg::Amd => write!(f, "amd"),
        }
    }
}

impl Display for CpuFeature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            // SIMD (x86)
            CpuFeature::SSE => "SSE",
            CpuFeature::SSE2 => "SSE2",
            CpuFeature::SSE3 => "SSE3",
            CpuFeature::SSSE3 => "SSSE3",
            CpuFeature::SSE4_1 => "SSE4_1",
            CpuFeature::SSE4_2 => "SSE4_2",
            CpuFeature::AVX => "AVX",
            CpuFeature::AVX2 => "AVX2",
            CpuFeature::FMA => "FMA",
            CpuFeature::F16C => "F16C",
            CpuFeature::AVX512F => "AVX512F",
            CpuFeature::AVX512VNNI => "AVX512VNNI",
            CpuFeature::AVX512BF16 => "AVX512BF16",
            CpuFeature::AVXVNNI => "AVXVNNI",
            // SIMD (ARM)
            CpuFeature::NEON => "NEON",
            CpuFeature::SVE => "SVE",
            CpuFeature::SVE2 => "SVE2",
            // Crypto
            CpuFeature::AES => "AES",
            CpuFeature::SHA => "SHA",
            CpuFeature::SHA512 => "SHA512",
            CpuFeature::PCLMULQDQ => "PCLMULQDQ",
            CpuFeature::RNG => "RNG",
            CpuFeature::GFNI => "GFNI",
            CpuFeature::VAES => "VAES",
            CpuFeature::VPCLMULQDQ => "VPCLMULQDQ",
            // Virtualization
            CpuFeature::VMX => "VMX",
            CpuFeature::NestedVirt => "NestedVirt",
            // AI/ML
            CpuFeature::AMX => "AMX",
            CpuFeature::SME => "SME",
            // Confidential computing
            CpuFeature::SGX => "SGX",
            CpuFeature::SEV => "SEV",
            CpuFeature::TDX => "TDX",
            // iGPU video encode
            CpuFeature::EncodeH264 => "EncodeH264",
            CpuFeature::EncodeHEVC => "EncodeHEVC",
            CpuFeature::EncodeAV1 => "EncodeAV1",
            CpuFeature::EncodeVP9 => "EncodeVP9",
            CpuFeature::EncodeJPEG => "EncodeJPEG",
            // iGPU video decode
            CpuFeature::DecodeH264 => "DecodeH264",
            CpuFeature::DecodeHEVC => "DecodeHEVC",
            CpuFeature::DecodeAV1 => "DecodeAV1",
            CpuFeature::DecodeVP9 => "DecodeVP9",
            CpuFeature::DecodeJPEG => "DecodeJPEG",
            CpuFeature::DecodeMPEG2 => "DecodeMPEG2",
            CpuFeature::DecodeVC1 => "DecodeVC1",
            // Video processing
            CpuFeature::VideoScaling => "VideoScaling",
            CpuFeature::VideoDeinterlace => "VideoDeinterlace",
            CpuFeature::VideoCSC => "VideoCSC",
            CpuFeature::VideoComposition => "VideoComposition",
        };
        f.write_str(s)
    }
}

impl FromStr for CpuFeature {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            // SIMD (x86)
            "SSE" => Ok(CpuFeature::SSE),
            "SSE2" => Ok(CpuFeature::SSE2),
            "SSE3" => Ok(CpuFeature::SSE3),
            "SSSE3" => Ok(CpuFeature::SSSE3),
            "SSE4_1" => Ok(CpuFeature::SSE4_1),
            "SSE4_2" => Ok(CpuFeature::SSE4_2),
            "AVX" => Ok(CpuFeature::AVX),
            "AVX2" => Ok(CpuFeature::AVX2),
            "FMA" => Ok(CpuFeature::FMA),
            "F16C" => Ok(CpuFeature::F16C),
            "AVX512F" => Ok(CpuFeature::AVX512F),
            "AVX512VNNI" => Ok(CpuFeature::AVX512VNNI),
            "AVX512BF16" => Ok(CpuFeature::AVX512BF16),
            "AVXVNNI" => Ok(CpuFeature::AVXVNNI),
            // SIMD (ARM)
            "NEON" => Ok(CpuFeature::NEON),
            "SVE" => Ok(CpuFeature::SVE),
            "SVE2" => Ok(CpuFeature::SVE2),
            // Crypto
            "AES" => Ok(CpuFeature::AES),
            "SHA" => Ok(CpuFeature::SHA),
            "SHA512" => Ok(CpuFeature::SHA512),
            "PCLMULQDQ" => Ok(CpuFeature::PCLMULQDQ),
            "RNG" => Ok(CpuFeature::RNG),
            "GFNI" => Ok(CpuFeature::GFNI),
            "VAES" => Ok(CpuFeature::VAES),
            "VPCLMULQDQ" => Ok(CpuFeature::VPCLMULQDQ),
            // Virtualization
            "VMX" => Ok(CpuFeature::VMX),
            "NestedVirt" => Ok(CpuFeature::NestedVirt),
            // AI/ML
            "AMX" => Ok(CpuFeature::AMX),
            "SME" => Ok(CpuFeature::SME),
            // Confidential computing
            "SGX" => Ok(CpuFeature::SGX),
            "SEV" => Ok(CpuFeature::SEV),
            "TDX" => Ok(CpuFeature::TDX),
            // iGPU video encode
            "EncodeH264" => Ok(CpuFeature::EncodeH264),
            "EncodeHEVC" => Ok(CpuFeature::EncodeHEVC),
            "EncodeAV1" => Ok(CpuFeature::EncodeAV1),
            "EncodeVP9" => Ok(CpuFeature::EncodeVP9),
            "EncodeJPEG" => Ok(CpuFeature::EncodeJPEG),
            // iGPU video decode
            "DecodeH264" => Ok(CpuFeature::DecodeH264),
            "DecodeHEVC" => Ok(CpuFeature::DecodeHEVC),
            "DecodeAV1" => Ok(CpuFeature::DecodeAV1),
            "DecodeVP9" => Ok(CpuFeature::DecodeVP9),
            "DecodeJPEG" => Ok(CpuFeature::DecodeJPEG),
            "DecodeMPEG2" => Ok(CpuFeature::DecodeMPEG2),
            "DecodeVC1" => Ok(CpuFeature::DecodeVC1),
            // Video processing
            "VideoScaling" => Ok(CpuFeature::VideoScaling),
            "VideoDeinterlace" => Ok(CpuFeature::VideoDeinterlace),
            "VideoCSC" => Ok(CpuFeature::VideoCSC),
            "VideoComposition" => Ok(CpuFeature::VideoComposition),
            other => Err(format!("unknown CpuFeature: {}", other)),
        }
    }
}

#[derive(FromRow, Clone, Debug)]
pub struct Region {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub company_id: u64,
}

#[derive(FromRow, Clone, Debug, Default)]
/// A VM host
pub struct VmHost {
    /// Unique id of this host
    pub id: u64,
    /// The host kind (Hypervisor)
    pub kind: VmHostKind,
    /// What region / group this host is part of
    pub region_id: u64,
    /// Internal name of this host
    pub name: String,
    /// Endpoint for controlling this host
    pub ip: String,
    /// Total number of CPU cores
    pub cpu: u16,
    pub cpu_mfg: CpuMfg,
    pub cpu_arch: CpuArch,
    pub cpu_features: CommaSeparated<CpuFeature>,
    /// Total memory size in bytes
    pub memory: u64,
    /// If VM's should be provisioned on this host
    pub enabled: bool,
    /// API token used to control this host via [ip] (encrypted)
    pub api_token: EncryptedString,
    /// CPU load factor for provisioning
    pub load_cpu: f32,
    /// Memory load factor
    pub load_memory: f32,
    /// Disk load factor
    pub load_disk: f32,
    /// VLAN id assigned to all vms on the host
    pub vlan_id: Option<u64>,
    /// MTU setting for network configuration
    pub mtu: Option<u16>,
    /// SSH username for running host utilities (default: root)
    pub ssh_user: Option<String>,
    /// SSH private key for running host utilities (encrypted, PEM format)
    pub ssh_key: Option<EncryptedString>,
    /// When set, the host is being "sunset": setting this date also forces the
    /// host `enabled = false` (so it takes no new VMs), and renewals are blocked
    /// once a VM's expiry reaches this date.
    pub sunset_date: Option<DateTime<Utc>>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct VmHostDisk {
    pub id: u64,
    pub host_id: u64,
    pub name: String,
    pub size: u64,
    pub kind: DiskType,
    pub interface: DiskInterface,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DiskType {
    #[default]
    HDD = 0,
    SSD = 1,
}

/// Unified struct containing all VM host data needed for admin purposes
#[derive(FromRow, Clone, Debug)]
pub struct AdminVmHost {
    #[sqlx(flatten)]
    pub host: VmHost,

    // Region fields with prefixed names to avoid conflicts
    pub region_id: u64,
    #[sqlx(rename = "region_name")]
    pub region_name: String,
    #[sqlx(rename = "region_enabled")]
    pub region_enabled: bool,
    #[sqlx(rename = "region_company_id")]
    pub region_company_id: u64,

    // Disk information (populated separately, not from SQL)
    #[sqlx(skip)]
    pub disks: Vec<VmHostDisk>,

    // Additional calculated data that can be populated by the database function
    pub active_vm_count: i64,
}

impl FromStr for DiskType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hdd" => Ok(DiskType::HDD),
            "ssd" => Ok(DiskType::SSD),
            _ => Err(anyhow!("unknown disk type {}", s)),
        }
    }
}

impl Display for DiskType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DiskType::HDD => write!(f, "hdd"),
            DiskType::SSD => write!(f, "ssd"),
        }
    }
}

#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DiskInterface {
    #[default]
    SATA = 0,
    SCSI = 1,
    PCIe = 2,
}

impl FromStr for DiskInterface {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sata" => Ok(DiskInterface::SATA),
            "scsi" => Ok(DiskInterface::SCSI),
            "pcie" => Ok(DiskInterface::PCIe),
            _ => Err(anyhow!("unknown disk interface {}", s)),
        }
    }
}

impl Display for DiskInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DiskInterface::SATA => write!(f, "sata"),
            DiskInterface::SCSI => write!(f, "scsi"),
            DiskInterface::PCIe => write!(f, "pcie"),
        }
    }
}

#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum OsDistribution {
    #[default]
    Ubuntu = 0,
    Debian = 1,
    CentOS = 2,
    Fedora = 3,
    FreeBSD = 4,
    OpenSUSE = 5,
    ArchLinux = 6,
    RedHatEnterprise = 7,
    AlmaLinux = 8,
    RockyLinux = 9,
    Alpine = 10,
    NixOS = 11,
    OpenBSD = 12,
    NetBSD = 13,
    Gentoo = 14,
    VoidLinux = 15,
}

impl FromStr for OsDistribution {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ubuntu" => Ok(OsDistribution::Ubuntu),
            "debian" => Ok(OsDistribution::Debian),
            "centos" => Ok(OsDistribution::CentOS),
            "fedora" => Ok(OsDistribution::Fedora),
            "freebsd" => Ok(OsDistribution::FreeBSD),
            "opensuse" => Ok(OsDistribution::OpenSUSE),
            "archlinux" => Ok(OsDistribution::ArchLinux),
            "redhatenterprise" => Ok(OsDistribution::RedHatEnterprise),
            "almalinux" => Ok(OsDistribution::AlmaLinux),
            "rockylinux" => Ok(OsDistribution::RockyLinux),
            "alpine" => Ok(OsDistribution::Alpine),
            "nixos" => Ok(OsDistribution::NixOS),
            "openbsd" => Ok(OsDistribution::OpenBSD),
            "netbsd" => Ok(OsDistribution::NetBSD),
            "gentoo" => Ok(OsDistribution::Gentoo),
            "voidlinux" => Ok(OsDistribution::VoidLinux),
            _ => Err(anyhow!("unknown distribution {}", s)),
        }
    }
}

impl Display for OsDistribution {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OsDistribution::Ubuntu => write!(f, "Ubuntu"),
            OsDistribution::Debian => write!(f, "Debian"),
            OsDistribution::CentOS => write!(f, "CentOs"),
            OsDistribution::Fedora => write!(f, "Fedora"),
            OsDistribution::FreeBSD => write!(f, "FreeBSD"),
            OsDistribution::OpenSUSE => write!(f, "OpenSuse"),
            OsDistribution::ArchLinux => write!(f, "Arch Linux"),
            OsDistribution::RedHatEnterprise => write!(f, "Red Hat Enterprise"),
            OsDistribution::AlmaLinux => write!(f, "AlmaLinux"),
            OsDistribution::RockyLinux => write!(f, "Rocky Linux"),
            OsDistribution::Alpine => write!(f, "Alpine"),
            OsDistribution::NixOS => write!(f, "NixOS"),
            OsDistribution::OpenBSD => write!(f, "OpenBSD"),
            OsDistribution::NetBSD => write!(f, "NetBSD"),
            OsDistribution::Gentoo => write!(f, "Gentoo"),
            OsDistribution::VoidLinux => write!(f, "Void Linux"),
        }
    }
}

/// OS Images are templates which are used as a basis for
/// provisioning new vms
#[derive(FromRow, Clone, Debug)]
pub struct VmOsImage {
    pub id: u64,
    pub distribution: OsDistribution,
    pub flavour: String,
    pub version: String,
    pub enabled: bool,
    pub release_date: DateTime<Utc>,
    /// URL location of cloud image
    pub url: String,
    /// CPU architecture this image targets (x86_64 / arm64)
    pub cpu_arch: CpuArch,
    pub default_username: Option<String>,
    /// SHA-2 checksum (SHA-256, SHA-384, or SHA-512) for image verification
    pub sha2: Option<String>,
    /// URL to the SHA-2 checksums file (e.g., SHA512SUMS)
    pub sha2_url: Option<String>,
}

/// Compression extensions recognised on OS image URLs. Files ending with one
/// of these are downloaded compressed and decompressed on the host before use.
pub const OS_IMAGE_COMPRESSION_EXTENSIONS: &[&str] =
    &["xz", "lzma", "zst", "zstd", "gz", "bz2", "lzo"];

impl VmOsImage {
    /// The compression algorithm (lower-case extension) if the image URL points
    /// to a compressed file (e.g. `.xz`, `.zst`, `.gz`, `.bz2`, `.lzo`).
    ///
    /// Returns `None` for uncompressed images.
    pub fn compression(&self) -> Option<String> {
        let name = self.url_filename().ok()?;
        let ext = std::path::Path::new(&name)
            .extension()?
            .to_str()?
            .to_lowercase();
        if OS_IMAGE_COMPRESSION_EXTENSIONS.contains(&ext.as_str()) {
            Some(ext)
        } else {
            None
        }
    }

    /// The filename as it will be stored on the host (original extension, and any
    /// compression extension, replaced with `.img`).
    ///
    /// Examples:
    /// - `foo.qcow2` -> `foo.img`
    /// - `foo.qcow2.xz` -> `foo.img`
    pub fn filename(&self) -> Result<String> {
        let url_name = self.url_filename()?;
        let mut name = PathBuf::from(&url_name);
        // Strip a compression extension first (e.g. foo.qcow2.xz -> foo.qcow2)
        // before replacing the remaining extension with `.img`.
        if self.compression().is_some() {
            name.set_extension("");
        }
        name.set_extension("img");
        Ok(name.to_string_lossy().to_string())
    }

    /// The original filename from the download URL, as it appears in SHASUMS files.
    pub fn url_filename(&self) -> Result<String> {
        let u: Url = self.url.parse()?;
        u.path_segments()
            .ok_or(anyhow!("Invalid URL"))?
            .next_back()
            .ok_or(anyhow!("Invalid URL"))
            .map(str::to_owned)
    }
}

impl Display for VmOsImage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {}", self.distribution, self.version)
    }
}

#[derive(FromRow, Clone, Debug)]
pub struct Router {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub kind: RouterKind,
    pub url: String,
    pub token: EncryptedString,
}

#[derive(Debug, Clone, sqlx::Type)]
#[repr(u16)]
pub enum RouterKind {
    /// Mikrotik router (JSON-Api)
    Mikrotik = 0,
    /// A pseudo-router which allows adding virtual mac addresses to a dedicated server
    OvhAdditionalIp = 1,
    /// A Linux machine managed over SSH (BIRD/Pathvector routing, iproute2 tunnels)
    LinuxSsh = 2,
    /// Mock router access in tests
    MockRouter = u16::MAX,
}

/// An external DNS provider used to manage forward (A/AAAA) and/or reverse (PTR)
/// records for IP assignments. Configured per-row in the database and referenced
/// from `ip_range` (see `forward_dns_server_id` / `reverse_dns_server_id`).
#[derive(FromRow, Clone, Debug)]
pub struct DnsServer {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub kind: DnsServerKind,
    /// API base url (provider specific). May be empty for providers with a fixed endpoint.
    pub url: String,
    /// Encrypted credential token (Cloudflare: bearer token; OVH: app_key:app_secret:consumer_key)
    pub token: EncryptedString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[repr(u16)]
pub enum DnsServerKind {
    /// Cloudflare DNS (zone + record based, forward & reverse)
    Cloudflare = 0,
    /// OVH reverse DNS (per-IP PTR records, reverse only)
    Ovh = 1,
    /// Mock DNS server for tests
    MockDns = u16::MAX,
}

/// Cached tunnel inventory discovered on a router (GRE/VXLAN/WireGuard)
#[derive(FromRow, Clone, Debug)]
pub struct RouterTunnel {
    pub id: u64,
    pub router_id: u64,
    /// Tunnel interface name
    pub name: String,
    pub kind: RouterTunnelKind,
    pub local_addr: Option<String>,
    pub remote_addr: Option<String>,
    pub enabled: bool,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, sqlx::Type, PartialEq, Eq)]
#[repr(u16)]
pub enum RouterTunnelKind {
    Gre = 0,
    Vxlan = 1,
    Wireguard = 2,
}

/// A single per-tunnel traffic sample. Tunnel interface counters are the
/// canonical source of per-session traffic for route servers (BGP has none).
#[derive(FromRow, Clone, Debug)]
pub struct RouterTunnelTraffic {
    pub id: u64,
    pub router_id: u64,
    pub tunnel_name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub sampled_at: DateTime<Utc>,
}

/// Cached BGP session discovery state (no byte counters)
#[derive(FromRow, Clone, Debug)]
pub struct RouterBgpSession {
    pub id: u64,
    pub router_id: u64,
    pub name: String,
    pub peer_ip: Option<String>,
    pub peer_asn: Option<u32>,
    pub local_asn: Option<u32>,
    pub state: String,
    pub prefixes_received: Option<u64>,
    pub prefixes_sent: Option<u64>,
    pub enabled: bool,
    pub direction: RouterBgpDirection,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, sqlx::Type, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum RouterBgpDirection {
    #[default]
    Unknown = 0,
    Upstream = 1,
    Downstream = 2,
    Peer = 3,
}

/// Cached BGP route table entry for a router: a prefix the router
/// originates/announces, or the detected default route.
#[derive(FromRow, Clone, Debug)]
pub struct RouterBgpRoute {
    pub id: u64,
    pub router_id: u64,
    /// Destination prefix in CIDR notation
    pub prefix: String,
    /// Next hop / gateway, if any
    pub next_hop: Option<String>,
    /// Whether this entry is the router's default route
    pub is_default: bool,
    pub last_seen: DateTime<Utc>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct IpRange {
    pub id: u64,
    pub cidr: String,
    pub gateway: String,
    pub enabled: bool,
    pub region_id: u64,
    pub reverse_zone_id: Option<String>,
    pub access_policy_id: Option<u64>,
    pub allocation_mode: IpRangeAllocationMode,
    /// Use all IPs in the range, including first and last
    pub use_full_range: bool,
    /// DNS server used to manage forward (A/AAAA) records for IPs in this range
    pub forward_dns_server_id: Option<u64>,
    /// DNS server used to manage reverse (PTR) records for IPs in this range
    pub reverse_dns_server_id: Option<u64>,
    /// Forward zone id (provider specific, e.g. Cloudflare zone id) for forward records
    pub forward_zone_id: Option<String>,
}

#[derive(Debug, Clone, Copy, sqlx::Type, Default)]
#[repr(u16)]
/// How ips are allocated from this range
pub enum IpRangeAllocationMode {
    /// IPs are assigned in a random order
    Random = 0,
    #[default]
    /// IPs are assigned in sequential order
    Sequential = 1,
    /// IP(v6) assignment uses SLAAC EUI-64
    SlaacEui64 = 2,
}

#[derive(FromRow, Clone, Debug)]
pub struct AccessPolicy {
    pub id: u64,
    pub name: String,
    pub kind: NetworkAccessPolicy,
    /// Router used to apply this network access policy
    pub router_id: Option<u64>,
    /// Interface name used to apply this policy
    pub interface: Option<String>,
}

/// Policy that determines how packets arrive at the VM
#[derive(Debug, Clone, Copy, sqlx::Type)]
#[repr(u16)]
pub enum NetworkAccessPolicy {
    /// ARP entries are added statically on the access router
    StaticArp = 0,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[repr(u16)]
pub enum IntervalType {
    Day = 0,
    Month = 1,
    Year = 2,
}

/// The kind of resource a cost record is attached to (weak/polymorphic link).
#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::Type, Serialize, Deserialize, Default)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum CostResourceType {
    /// Links to `vm_host.id`
    #[default]
    VmHost = 0,
    /// Links to `ip_range.id`
    IpRange = 1,
    /// Not tied to any internal entity — a free-form cost/subscription
    /// identified only by its user-supplied `label` (e.g. "Colo cross-connect",
    /// "Upstream transit"). `resource_id` is overloaded as the region id this
    /// cost is attributed to in the P/L report (0 = global / not
    /// region-specific, excluded from region-filtered reports).
    Generic = 2,
}

impl Display for CostResourceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CostResourceType::VmHost => write!(f, "vm_host"),
            CostResourceType::IpRange => write!(f, "ip_range"),
            CostResourceType::Generic => write!(f, "generic"),
        }
    }
}

impl FromStr for CostResourceType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vm_host" | "host" => Ok(CostResourceType::VmHost),
            "ip_range" => Ok(CostResourceType::IpRange),
            "generic" | "subscription" => Ok(CostResourceType::Generic),
            _ => Err(anyhow!("unknown cost resource type: {}", s)),
        }
    }
}

/// Whether a cost is a recurring charge or a one-time capital outlay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::Type, Serialize, Deserialize, Default)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum CostType {
    /// Recurring cost billed every `interval_amount` `interval_type` (rent/colo,
    /// or the whole-block monthly cost for an ip_range).
    #[default]
    Recurring = 0,
    /// One-time capital investment (e.g. hardware purchase) used for break-even.
    OneTime = 1,
}

impl Display for CostType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CostType::Recurring => write!(f, "recurring"),
            CostType::OneTime => write!(f, "one_time"),
        }
    }
}

impl FromStr for CostType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "recurring" => Ok(CostType::Recurring),
            "one_time" | "onetime" | "investment" => Ok(CostType::OneTime),
            _ => Err(anyhow!("unknown cost type: {}", s)),
        }
    }
}

/// An optional cost record weakly linked to another resource by
/// `(resource_type, resource_id)`. Used to compute P/L; admin-only, never
/// exposed to end users. Costs are all in `amount` smallest currency units.
#[derive(FromRow, Clone, Debug)]
pub struct ResourceCost {
    pub id: u64,
    /// What kind of resource this cost is attached to
    pub resource_type: CostResourceType,
    /// Id of the resource within its table (weak link, no FK). For `Generic`
    /// costs (identified by `label`) this is overloaded as the region id the
    /// cost is attributed to in the P/L report (0 = global).
    pub resource_id: u64,
    /// Free-form label for costs not tied to an internal entity (required for
    /// `Generic`; optional/ignored for entity-linked costs).
    pub label: Option<String>,
    /// Recurring vs one-time capital cost
    pub cost_type: CostType,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC).
    /// For an `ip_range` recurring cost this is the cost of the entire block
    /// (charged regardless of how many IPs are assigned).
    pub amount: u64,
    /// Currency code (e.g. USD, EUR)
    pub currency: String,
    /// Number of intervals per billing cycle (e.g. 1 for "every 1 month").
    /// NULL for one-time costs.
    pub interval_amount: Option<u64>,
    /// Interval unit (Day, Month, Year). NULL for one-time costs.
    pub interval_type: Option<IntervalType>,
    /// Date the cost starts / the one-time purchase was made.
    pub billing_start: Option<DateTime<Utc>>,
    /// Date the recurring cost stops being paid. `None` = still active/ongoing.
    /// Only counts towards P/L while now() is within `[billing_start, billing_end)`.
    pub billing_end: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

#[derive(FromRow, Clone, Debug)]
pub struct VmCostPlan {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: IntervalType,
}

/// Offers.
/// These are the same as the offers visible to customers
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmTemplate {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    pub cpu_mfg: CpuMfg,
    pub cpu_arch: CpuArch,
    pub cpu_features: CommaSeparated<CpuFeature>,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: DiskType,
    pub disk_interface: DiskInterface,
    pub cost_plan_id: u64,
    pub region_id: u64,
    /// Maximum disk read IOPS (None = uncapped)
    pub disk_iops_read: Option<u32>,
    /// Maximum disk write IOPS (None = uncapped)
    pub disk_iops_write: Option<u32>,
    /// Maximum disk read throughput in MB/s (None = uncapped)
    pub disk_mbps_read: Option<u32>,
    /// Maximum disk write throughput in MB/s (None = uncapped)
    pub disk_mbps_write: Option<u32>,
    /// Maximum network bandwidth in Mbit/s (None = uncapped)
    pub network_mbps: Option<u32>,
    /// Maximum CPU usage as a fraction of allocated cores (e.g. 0.5 = 50%; None = uncapped)
    pub cpu_limit: Option<f32>,
    /// Maximum number of user firewall rules per VM (None = use global default)
    pub firewall_rule_limit: Option<u16>,
}

/// A custom pricing template, used for billing calculation of a specific VM
/// This mostly just stores the number of resources assigned and the specific pricing used
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmCustomTemplate {
    pub id: u64,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: DiskType,
    pub disk_interface: DiskInterface,
    pub pricing_id: u64,
    pub cpu_mfg: CpuMfg,
    pub cpu_arch: CpuArch,
    pub cpu_features: CommaSeparated<CpuFeature>,
    /// Maximum disk read IOPS (None = uncapped)
    pub disk_iops_read: Option<u32>,
    /// Maximum disk write IOPS (None = uncapped)
    pub disk_iops_write: Option<u32>,
    /// Maximum disk read throughput in MB/s (None = uncapped)
    pub disk_mbps_read: Option<u32>,
    /// Maximum disk write throughput in MB/s (None = uncapped)
    pub disk_mbps_write: Option<u32>,
    /// Maximum network bandwidth in Mbit/s (None = uncapped)
    pub network_mbps: Option<u32>,
    /// Maximum CPU usage as a fraction of allocated cores (e.g. 0.5 = 50%; None = uncapped)
    pub cpu_limit: Option<f32>,
    /// Maximum number of user firewall rules per VM (None = use global default)
    pub firewall_rule_limit: Option<u16>,
}

/// Custom pricing template, usually 1 per region
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmCustomPricing {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub region_id: u64,
    pub currency: String,
    pub cpu_mfg: CpuMfg,
    pub cpu_arch: CpuArch,
    pub cpu_features: CommaSeparated<CpuFeature>,
    /// Cost per CPU core in smallest currency units (cents for fiat, millisats for BTC)
    pub cpu_cost: u64,
    /// Cost per GB ram in smallest currency units (cents for fiat, millisats for BTC)
    pub memory_cost: u64,
    /// Cost per IPv4 address in smallest currency units (cents for fiat, millisats for BTC)
    pub ip4_cost: u64,
    /// Cost per IPv6 address in smallest currency units (cents for fiat, millisats for BTC)
    pub ip6_cost: u64,
    /// Minimum CPU cores allowed
    pub min_cpu: u16,
    /// Maximum CPU cores allowed
    pub max_cpu: u16,
    /// Minimum memory in bytes
    pub min_memory: u64,
    /// Maximum memory in bytes
    pub max_memory: u64,
    /// Maximum disk read IOPS (None = uncapped)
    pub disk_iops_read: Option<u32>,
    /// Maximum disk write IOPS (None = uncapped)
    pub disk_iops_write: Option<u32>,
    /// Maximum disk read throughput in MB/s (None = uncapped)
    pub disk_mbps_read: Option<u32>,
    /// Maximum disk write throughput in MB/s (None = uncapped)
    pub disk_mbps_write: Option<u32>,
    /// Maximum network bandwidth in Mbit/s (None = uncapped)
    pub network_mbps: Option<u32>,
    /// Maximum CPU usage as a fraction of allocated cores (e.g. 0.5 = 50%; None = uncapped)
    pub cpu_limit: Option<f32>,
}

/// Pricing per GB on a disk type (SSD/HDD)
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmCustomPricingDisk {
    pub id: u64,
    pub pricing_id: u64,
    pub kind: DiskType,
    pub interface: DiskInterface,
    /// Cost per GB in smallest currency units (cents for fiat, millisats for BTC)
    pub cost: u64,
    /// Minimum disk size in bytes for this disk type/interface
    pub min_disk_size: u64,
    /// Maximum disk size in bytes for this disk type/interface
    pub max_disk_size: u64,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct Vm {
    /// Unique VM ID (Same in proxmox)
    pub id: u64,
    /// The host this VM is on
    pub host_id: u64,
    /// The user that owns this VM
    pub user_id: u64,
    /// The base image of this VM
    pub image_id: u64,
    /// The base image of this VM [VmTemplate]
    pub template_id: Option<u64>,
    /// Custom pricing specification used for this vm [VmCustomTemplate]
    pub custom_template_id: Option<u64>,
    /// The subscription line item managing billing for this VM (mirrors ip_range_subscription pattern)
    pub subscription_line_item_id: u64,
    /// Users ssh-key assigned to this VM (None once the VM is deleted)
    pub ssh_key_id: Option<u64>,
    /// The [VmHostDisk] this VM is on
    pub disk_id: u64,
    /// Network MAC address
    pub mac_address: String,
    /// Is the VM deleted
    pub deleted: bool,
    /// Referral code (recorded during ordering)
    pub ref_code: Option<String>,
    /// Whether the VM is disabled by admin
    pub disabled: bool,
    /// Default inbound firewall policy (None = inherit host default / accept)
    pub fw_policy_in: Option<VmFirewallPolicy>,
    /// Default outbound firewall policy (None = inherit host default / accept)
    pub fw_policy_out: Option<VmFirewallPolicy>,
    /// Free-form admin-only notes about this VM (not exposed to the customer)
    pub admin_notes: Option<String>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct VmIpAssignment {
    /// Unique id of this assignment
    pub id: u64,
    /// VM id this IP is assigned to
    pub vm_id: u64,
    /// IP range id
    pub ip_range_id: u64,
    /// The IP address (v4/v6)
    pub ip: String,
    /// If this record was freed
    pub deleted: bool,
    /// External ID pointing to a static arp entry on the router
    pub arp_ref: Option<String>,
    /// Forward DNS FQDN
    pub dns_forward: Option<String>,
    /// External ID pointing to the forward DNS entry for this IP
    pub dns_forward_ref: Option<String>,
    /// Reverse DNS FQDN
    pub dns_reverse: Option<String>,
    /// External ID pointing to the reverse DNS entry for this IP
    pub dns_reverse_ref: Option<String>,
}

impl Display for VmIpAssignment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip)
    }
}

/// Direction a firewall rule applies to
#[derive(Debug, Clone, Copy, sqlx::Type, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum VmFirewallDirection {
    /// Traffic arriving at the VM
    #[default]
    Inbound = 0,
    /// Traffic leaving the VM
    Outbound = 1,
}

/// Protocol a firewall rule matches
#[derive(Debug, Clone, Copy, sqlx::Type, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum VmFirewallProtocol {
    /// Match any protocol
    #[default]
    Any = 0,
    Tcp = 1,
    Udp = 2,
    Icmp = 3,
}

/// Action taken when a firewall rule matches
#[derive(Debug, Clone, Copy, sqlx::Type, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum VmFirewallRuleAction {
    /// Silently drop the packet
    Drop = 0,
    /// Accept the packet
    #[default]
    Accept = 1,
    /// Reject the packet (drop and send an ICMP/TCP-RST rejection)
    Reject = 2,
}

/// Default policy applied to traffic in a given direction when no rule matches
#[derive(Debug, Clone, Copy, sqlx::Type, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum VmFirewallPolicy {
    /// Accept the packet (allow-all default; current behaviour)
    #[default]
    Accept = 0,
    /// Silently drop the packet
    Drop = 1,
    /// Reject the packet (drop and send an ICMP/TCP-RST rejection)
    Reject = 2,
}

/// A user-configurable per-VM firewall rule (#36)
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmFirewallRule {
    /// Unique id of this rule
    pub id: u64,
    /// VM this rule applies to
    pub vm_id: u64,
    /// Evaluation order; lower priority is evaluated first
    pub priority: u16,
    /// Direction this rule applies to
    pub direction: VmFirewallDirection,
    /// Protocol matched by this rule
    pub protocol: VmFirewallProtocol,
    /// Action taken when the rule matches
    pub action: VmFirewallRuleAction,
    /// Optional source CIDR (None = any)
    pub src_cidr: Option<String>,
    /// Optional inclusive destination port range start (None = any)
    pub dst_port_start: Option<u32>,
    /// Optional inclusive destination port range end (None = any)
    pub dst_port_end: Option<u32>,
    /// Whether this rule is active
    pub enabled: bool,
    /// When this rule was created
    pub created: DateTime<Utc>,
    /// When this rule was last updated
    pub updated: DateTime<Utc>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct Referral {
    /// Unique id of this referral entry
    pub id: u64,
    /// The user that owns this referral
    pub user_id: u64,
    /// The auto-generated referral code (base63, 8 characters)
    pub code: String,
    /// Payout target address. Its type is determined by `mode`: a Lightning
    /// address for `LightningAddress`, an on-chain Bitcoin address for
    /// `OnChain`. `None` for modes that need no address (e.g. `Nwc`, which
    /// pays via the user's saved NWC connection).
    pub address: Option<String>,
    /// How the referrer is paid their commission.
    pub mode: ReferralPayoutMode,
    /// When this referral entry was created
    pub created: DateTime<Utc>,
    /// Optional per-referrer commission override, as a whole percentage of a
    /// referred VM's first payment. `None` falls back to the referred VM's
    /// `company.referral_rate` default.
    #[sqlx(default)]
    pub referral_rate: Option<f32>,
    /// Optional user-chosen minimum accrued commission (in **satoshis**) before
    /// an automated payout is made to this referrer. Lets referrers — on-chain
    /// ones in particular — avoid many tiny payouts by batching up to a larger
    /// amount. When set it must be at least the system minimum; the effective
    /// threshold used at payout time is `max(system_minimum, payout_threshold)`.
    /// `None` uses the system minimum.
    #[sqlx(default)]
    pub payout_threshold: Option<u64>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct ReferralPayout {
    /// Unique id of this payout record
    pub id: u64,
    /// The referral this payout belongs to
    pub referral_id: u64,
    /// Amount in smallest currency unit
    pub amount: u64,
    /// Network/routing fee charged to the referrer, in the same smallest
    /// currency unit as `amount`. The referrer bears the fee: it is debited from
    /// their balance together with `amount` when computing what remains owed, so
    /// a fee-induced deficit is recovered from future commission.
    #[sqlx(default)]
    pub fee: u64,
    /// Currency of this payout
    pub currency: String,
    /// When this payout record was created
    pub created: DateTime<Utc>,
    /// Whether this payout has been completed
    pub is_paid: bool,
    /// How the payout was made, recorded for reference so `output` can be
    /// interpreted without joining to the referral.
    #[sqlx(default)]
    pub mode: ReferralPayoutMode,
    /// The payout's output reference: a BOLT11 invoice for a Lightning payout,
    /// or the on-chain outpoint (`"{txid}:{vout}"`) for an on-chain payout.
    ///
    /// On-chain payouts batch every eligible referrer into a single send-many
    /// transaction, so their outpoints share the `txid` but each carries the
    /// distinct `vout` of the output paying that referrer.
    #[sqlx(default)]
    pub output: Option<String>,
    /// Preimage revealed when a Lightning invoice was paid (32 bytes, SHA256).
    pub pre_image: Option<Vec<u8>>,
}

#[derive(FromRow, Clone, Debug)]
pub struct ReferralCostUsage {
    pub vm_id: u64,
    pub ref_code: String,
    pub created: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub rate: f32,
    pub base_currency: String,
    /// Effective commission rate applied to this referred VM's first payment, as
    /// a whole percentage: the referrer's override if set, else the referred
    /// VM's `company.referral_rate` default.
    #[sqlx(default)]
    pub effective_rate: f32,
}

impl ReferralCostUsage {
    /// Commission earned on this referral: `amount * effective_rate%`, floored,
    /// in the same smallest-currency unit as `amount`.
    pub fn commission(&self) -> u64 {
        ((self.amount as f64) * (self.effective_rate as f64 / 100.0)).floor() as u64
    }
}

/// How a referrer receives their commission payouts. Stored as a small integer;
/// new methods are added as new variants (append-only to preserve values).
#[derive(Type, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum ReferralPayoutMode {
    /// Pay to the referrer's Lightning address (LNURL-pay).
    #[default]
    LightningAddress = 0,
    /// Pay via the referrer's Nostr Wallet Connect (NWC) connection.
    Nwc = 1,
    /// Credit the referrer's account balance (not yet implemented).
    AccountCredit = 2,
    /// Pay to the referrer's on-chain Bitcoin address. Eligible referrers are
    /// batched into a single send-many transaction.
    OnChain = 3,
}

impl Display for ReferralPayoutMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReferralPayoutMode::LightningAddress => "lightning_address",
            ReferralPayoutMode::Nwc => "nwc",
            ReferralPayoutMode::AccountCredit => "account_credit",
            ReferralPayoutMode::OnChain => "on_chain",
        })
    }
}

impl FromStr for ReferralPayoutMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "lightning_address" | "lightning" | "lnaddress" => {
                Ok(ReferralPayoutMode::LightningAddress)
            }
            "nwc" => Ok(ReferralPayoutMode::Nwc),
            "account_credit" | "credit" => Ok(ReferralPayoutMode::AccountCredit),
            "on_chain" | "onchain" => Ok(ReferralPayoutMode::OnChain),
            other => anyhow::bail!("Invalid referral payout mode: {}", other),
        }
    }
}

#[derive(Type, Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum PaymentMethod {
    #[default]
    Lightning,
    Revolut,
    Paypal,
    Stripe,
    /// On-chain Bitcoin payments
    OnChain,
}

#[derive(Type, Clone, Copy, Debug, Default, PartialEq)]
#[repr(u16)]
pub enum PaymentType {
    #[default]
    Renewal = 0,
    Upgrade = 1,
}

impl Display for PaymentMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentMethod::Lightning => write!(f, "Lightning"),
            PaymentMethod::Revolut => write!(f, "Revolut"),
            PaymentMethod::Paypal => write!(f, "PayPal"),
            PaymentMethod::Stripe => write!(f, "Stripe"),
            PaymentMethod::OnChain => write!(f, "OnChain"),
        }
    }
}

impl FromStr for PaymentMethod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "lightning" => Ok(PaymentMethod::Lightning),
            "revolut" => Ok(PaymentMethod::Revolut),
            "paypal" => Ok(PaymentMethod::Paypal),
            "stripe" => Ok(PaymentMethod::Stripe),
            "onchain" => Ok(PaymentMethod::OnChain),
            _ => bail!("Unknown payment method: {}", s),
        }
    }
}

impl Display for PaymentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentType::Renewal => write!(f, "Renewal"),
            PaymentType::Upgrade => write!(f, "Upgrade"),
        }
    }
}

impl FromStr for PaymentType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "renewal" => Ok(PaymentType::Renewal),
            "upgrade" => Ok(PaymentType::Upgrade),
            _ => bail!("Unknown payment type: {}", s),
        }
    }
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct NostrDomain {
    pub id: u64,
    pub owner_id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    pub enabled: bool,
    pub relays: Option<String>,
    pub handles: i64,
    pub last_status_change: DateTime<Utc>,
    pub activation_hash: Option<String>,
    pub http_only: bool,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct NostrDomainHandle {
    pub id: u64,
    pub domain_id: u64,
    pub handle: String,
    pub created: DateTime<Utc>,
    pub pubkey: Vec<u8>,
    pub relays: Option<String>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct Company {
    pub id: u64,
    pub created: DateTime<Utc>,
    pub name: String,
    pub address_1: Option<String>,
    pub address_2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country_code: Option<String>,
    pub tax_id: Option<String>,
    pub postcode: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub base_currency: String,
    /// Default referral commission, as a whole percentage of a referred VM's
    /// first payment (e.g. `10.0` = 10%). Applies when the referrer has no
    /// per-referrer override. `0` disables commission for this company.
    #[sqlx(default)]
    pub referral_rate: f32,
    /// Maximum number of days a subscription may be prepaid/renewed in advance.
    /// A renewal is rejected once it would push the subscription expiry beyond
    /// `now + max_prepay_days`. `0` means "inherit the global default".
    #[sqlx(default)]
    pub max_prepay_days: u16,
}

#[derive(Clone, Debug, Default)]
pub struct RegionStats {
    pub host_count: u64,
    pub total_vms: u64,
    pub total_cpu_cores: u64,
    pub total_memory_bytes: u64,
    pub total_ip_assignments: u64,
}

#[derive(Clone, Debug, sqlx::Type)]
#[repr(u16)]
pub enum VmHistoryActionType {
    Created = 0,
    Started = 1,
    Stopped = 2,
    Restarted = 3,
    Deleted = 4,
    Expired = 5,
    Renewed = 6,
    Reinstalled = 7,
    StateChanged = 8,
    PaymentReceived = 9,
    ConfigurationChanged = 10,
    Transferred = 11,
}

impl Display for VmHistoryActionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VmHistoryActionType::Created => write!(f, "created"),
            VmHistoryActionType::Started => write!(f, "started"),
            VmHistoryActionType::Stopped => write!(f, "stopped"),
            VmHistoryActionType::Restarted => write!(f, "restarted"),
            VmHistoryActionType::Deleted => write!(f, "deleted"),
            VmHistoryActionType::Expired => write!(f, "expired"),
            VmHistoryActionType::Renewed => write!(f, "renewed"),
            VmHistoryActionType::Reinstalled => write!(f, "reinstalled"),
            VmHistoryActionType::StateChanged => write!(f, "state_changed"),
            VmHistoryActionType::PaymentReceived => write!(f, "payment_received"),
            VmHistoryActionType::ConfigurationChanged => write!(f, "configuration_changed"),
            VmHistoryActionType::Transferred => write!(f, "transferred"),
        }
    }
}

impl FromStr for VmHistoryActionType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "created" => Ok(VmHistoryActionType::Created),
            "started" => Ok(VmHistoryActionType::Started),
            "stopped" => Ok(VmHistoryActionType::Stopped),
            "restarted" => Ok(VmHistoryActionType::Restarted),
            "deleted" => Ok(VmHistoryActionType::Deleted),
            "expired" => Ok(VmHistoryActionType::Expired),
            "renewed" => Ok(VmHistoryActionType::Renewed),
            "reinstalled" => Ok(VmHistoryActionType::Reinstalled),
            "state_changed" => Ok(VmHistoryActionType::StateChanged),
            "payment_received" => Ok(VmHistoryActionType::PaymentReceived),
            "configuration_changed" => Ok(VmHistoryActionType::ConfigurationChanged),
            "transferred" => Ok(VmHistoryActionType::Transferred),
            _ => Err(anyhow!("unknown VM history action type: {}", s)),
        }
    }
}

#[derive(FromRow, Clone, Debug)]
pub struct VmHistory {
    pub id: u64,
    pub vm_id: u64,
    pub action_type: VmHistoryActionType,
    pub timestamp: DateTime<Utc>,
    pub initiated_by_user: Option<u64>,
    pub previous_state: Option<Vec<u8>>,
    pub new_state: Option<Vec<u8>>,
    pub metadata: Option<Vec<u8>>,
    pub description: Option<String>,
}

// RBAC Models

/// Administrative role definition
#[derive(FromRow, Clone, Debug)]
pub struct AdminRole {
    pub id: u64,
    pub name: String,
    pub description: Option<String>,
    pub is_system_role: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Role permission mapping
#[derive(FromRow, Clone, Debug)]
pub struct AdminRolePermission {
    pub id: u64,
    pub role_id: u64,
    pub resource: u16, // AdminResource enum value
    pub action: u16,   // AdminAction enum value
    pub created_at: DateTime<Utc>,
}

/// User role assignment
#[derive(FromRow, Clone, Debug)]
pub struct AdminRoleAssignment {
    pub id: u64,
    pub user_id: u64,
    pub role_id: u64,
    pub assigned_by: Option<u64>,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Administrative resources that can be managed
#[derive(Clone, Copy, Debug, sqlx::Type, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum AdminResource {
    Users = 0,
    VirtualMachines = 1,
    Hosts = 2,
    Payments = 3,
    Analytics = 4,
    System = 5,
    Roles = 6,
    Audit = 7,
    AccessPolicy = 8,
    Company = 9,
    IpRange = 10,
    Router = 11,
    VmCustomPricing = 12,
    HostRegion = 13,
    VmOsImage = 14,
    VmPayment = 15,
    VmTemplate = 16,
    Subscriptions = 17,
    SubscriptionLineItems = 18,
    SubscriptionPayments = 19,
    IpSpace = 20,
    PaymentMethodConfig = 21,
    DnsServer = 22,
    UserPaymentMethod = 23,
    ResourceCost = 24,
    Referral = 25,
    App = 26,
}

/// Actions that can be performed on administrative resources
#[derive(Clone, Copy, Debug, sqlx::Type, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum AdminAction {
    Create = 0,
    View = 1, // Covers both read single item and list multiple items
    Update = 2,
    Delete = 3,
    /// Bulk mutation across many resources at once (e.g. extend all VMs).
    /// Held separately from `Update` so a fleet-wide action can be granted
    /// independently of ordinary single-resource edits.
    BulkUpdate = 4,
}

impl Display for AdminResource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminResource::Users => write!(f, "users"),
            AdminResource::VirtualMachines => write!(f, "virtual_machines"),
            AdminResource::Hosts => write!(f, "hosts"),
            AdminResource::Payments => write!(f, "payments"),
            AdminResource::Analytics => write!(f, "analytics"),
            AdminResource::System => write!(f, "system"),
            AdminResource::Roles => write!(f, "roles"),
            AdminResource::Audit => write!(f, "audit"),
            AdminResource::AccessPolicy => write!(f, "access_policy"),
            AdminResource::Company => write!(f, "company"),
            AdminResource::IpRange => write!(f, "ip_range"),
            AdminResource::Router => write!(f, "router"),
            AdminResource::VmCustomPricing => write!(f, "vm_custom_pricing"),
            AdminResource::HostRegion => write!(f, "host_region"),
            AdminResource::VmOsImage => write!(f, "vm_os_image"),
            AdminResource::VmPayment => write!(f, "vm_payment"),
            AdminResource::VmTemplate => write!(f, "vm_template"),
            AdminResource::Subscriptions => write!(f, "subscriptions"),
            AdminResource::SubscriptionLineItems => write!(f, "subscription_line_items"),
            AdminResource::SubscriptionPayments => write!(f, "subscription_payments"),
            AdminResource::IpSpace => write!(f, "ip_space"),
            AdminResource::PaymentMethodConfig => write!(f, "payment_method_config"),
            AdminResource::DnsServer => write!(f, "dns_server"),
            AdminResource::UserPaymentMethod => write!(f, "user_payment_method"),
            AdminResource::ResourceCost => write!(f, "resource_cost"),
            AdminResource::Referral => write!(f, "referral"),
            AdminResource::App => write!(f, "app"),
        }
    }
}

impl FromStr for AdminResource {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "users" => Ok(AdminResource::Users),
            "virtual_machines" | "vms" => Ok(AdminResource::VirtualMachines),
            "hosts" => Ok(AdminResource::Hosts),
            "payments" => Ok(AdminResource::Payments),
            "analytics" => Ok(AdminResource::Analytics),
            "system" => Ok(AdminResource::System),
            "roles" => Ok(AdminResource::Roles),
            "audit" => Ok(AdminResource::Audit),
            "access_policy" => Ok(AdminResource::AccessPolicy),
            "company" => Ok(AdminResource::Company),
            "ip_range" => Ok(AdminResource::IpRange),
            "router" => Ok(AdminResource::Router),
            "vm_custom_pricing" => Ok(AdminResource::VmCustomPricing),
            "host_region" => Ok(AdminResource::HostRegion),
            "vm_os_image" => Ok(AdminResource::VmOsImage),
            "vm_payment" => Ok(AdminResource::VmPayment),
            "vm_template" => Ok(AdminResource::VmTemplate),
            "subscriptions" => Ok(AdminResource::Subscriptions),
            "subscription_line_items" => Ok(AdminResource::SubscriptionLineItems),
            "subscription_payments" => Ok(AdminResource::SubscriptionPayments),
            "ip_space" => Ok(AdminResource::IpSpace),
            "payment_method_config" => Ok(AdminResource::PaymentMethodConfig),
            "dns_server" => Ok(AdminResource::DnsServer),
            "user_payment_method" => Ok(AdminResource::UserPaymentMethod),
            "resource_cost" => Ok(AdminResource::ResourceCost),
            "referral" => Ok(AdminResource::Referral),
            "app" => Ok(AdminResource::App),
            _ => Err(anyhow!("unknown admin resource: {}", s)),
        }
    }
}

impl TryFrom<u16> for AdminResource {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AdminResource::Users),
            1 => Ok(AdminResource::VirtualMachines),
            2 => Ok(AdminResource::Hosts),
            3 => Ok(AdminResource::Payments),
            4 => Ok(AdminResource::Analytics),
            5 => Ok(AdminResource::System),
            6 => Ok(AdminResource::Roles),
            7 => Ok(AdminResource::Audit),
            8 => Ok(AdminResource::AccessPolicy),
            9 => Ok(AdminResource::Company),
            10 => Ok(AdminResource::IpRange),
            11 => Ok(AdminResource::Router),
            12 => Ok(AdminResource::VmCustomPricing),
            13 => Ok(AdminResource::HostRegion),
            14 => Ok(AdminResource::VmOsImage),
            15 => Ok(AdminResource::VmPayment),
            16 => Ok(AdminResource::VmTemplate),
            17 => Ok(AdminResource::Subscriptions),
            18 => Ok(AdminResource::SubscriptionLineItems),
            19 => Ok(AdminResource::SubscriptionPayments),
            20 => Ok(AdminResource::IpSpace),
            21 => Ok(AdminResource::PaymentMethodConfig),
            22 => Ok(AdminResource::DnsServer),
            23 => Ok(AdminResource::UserPaymentMethod),
            24 => Ok(AdminResource::ResourceCost),
            25 => Ok(AdminResource::Referral),
            26 => Ok(AdminResource::App),
            _ => Err(anyhow!("unknown admin resource value: {}", value)),
        }
    }
}

impl AdminResource {
    /// Get all available admin resources
    pub fn all() -> Vec<AdminResource> {
        vec![
            AdminResource::Users,
            AdminResource::VirtualMachines,
            AdminResource::Hosts,
            AdminResource::Payments,
            AdminResource::Analytics,
            AdminResource::System,
            AdminResource::Roles,
            AdminResource::Audit,
            AdminResource::AccessPolicy,
            AdminResource::Company,
            AdminResource::IpRange,
            AdminResource::Router,
            AdminResource::VmCustomPricing,
            AdminResource::HostRegion,
            AdminResource::VmOsImage,
            AdminResource::VmPayment,
            AdminResource::VmTemplate,
            AdminResource::Subscriptions,
            AdminResource::SubscriptionLineItems,
            AdminResource::SubscriptionPayments,
            AdminResource::IpSpace,
            AdminResource::PaymentMethodConfig,
            AdminResource::DnsServer,
            AdminResource::UserPaymentMethod,
            AdminResource::ResourceCost,
            AdminResource::Referral,
            AdminResource::App,
        ]
    }
}

impl Display for AdminAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminAction::Create => write!(f, "create"),
            AdminAction::View => write!(f, "view"),
            AdminAction::Update => write!(f, "update"),
            AdminAction::Delete => write!(f, "delete"),
            AdminAction::BulkUpdate => write!(f, "bulk_update"),
        }
    }
}

impl FromStr for AdminAction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(AdminAction::Create),
            "view" | "read" | "list" => Ok(AdminAction::View),
            "update" | "edit" => Ok(AdminAction::Update),
            "delete" | "remove" => Ok(AdminAction::Delete),
            "bulk_update" | "bulk" => Ok(AdminAction::BulkUpdate),
            _ => Err(anyhow!("unknown admin action: {}", s)),
        }
    }
}

impl TryFrom<u16> for AdminAction {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AdminAction::Create),
            1 => Ok(AdminAction::View),
            2 => Ok(AdminAction::Update),
            3 => Ok(AdminAction::Delete),
            4 => Ok(AdminAction::BulkUpdate),
            _ => Err(anyhow!("unknown admin action value: {}", value)),
        }
    }
}

impl AdminAction {
    /// Get all available admin actions
    pub fn all() -> Vec<AdminAction> {
        vec![
            AdminAction::Create,
            AdminAction::View,
            AdminAction::Update,
            AdminAction::Delete,
            AdminAction::BulkUpdate,
        ]
    }
}

// ============================================================================
// Subscription Billing System - Recurring services (LIR, ASN, etc.)
// ============================================================================

/// Subscription payment type (Purchase or Renewal)
#[derive(Type, Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum SubscriptionPaymentType {
    /// Initial purchase including setup fees
    #[default]
    Purchase = 0,
    /// Recurring renewal payment
    Renewal = 1,
    /// VM upgrade payment
    Upgrade = 2,
}

impl Display for SubscriptionPaymentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionPaymentType::Purchase => write!(f, "Purchase"),
            SubscriptionPaymentType::Renewal => write!(f, "Renewal"),
            SubscriptionPaymentType::Upgrade => write!(f, "Upgrade"),
        }
    }
}

/// Subscription for a recurring service
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub id: u64,
    pub user_id: u64,
    pub company_id: u64,
    pub name: String,
    pub description: Option<String>,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub is_active: bool,
    /// Whether the initial setup (purchase) payment has been confirmed.
    /// Used to determine if setup fees apply on the next renewal invoice.
    pub is_setup: bool,
    pub currency: String,
    /// Number of intervals per billing cycle (e.g. 1 for "every 1 month")
    pub interval_amount: u64,
    /// Interval unit (Day, Month, Year)
    pub interval_type: IntervalType,
    pub setup_fee: u64,
    pub auto_renewal_enabled: bool,
    pub external_id: Option<String>,
}

/// Subscription Type - Type of service being sold
#[derive(Clone, Copy, Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionType {
    IpRange = 0,       // IP range allocation/LIR services
    AsnSponsoring = 1, // ASN sponsoring services
    DnsHosting = 2,    // DNS hosting services
    Vps = 3,           // VM (links to vm table via vm.subscription_line_item_id)
    App = 4, // Managed app deployment (links via app_deployment.subscription_line_item_id)
}

impl Display for SubscriptionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionType::IpRange => write!(f, "IP Range"),
            SubscriptionType::AsnSponsoring => write!(f, "ASN Sponsoring"),
            SubscriptionType::DnsHosting => write!(f, "DNS Hosting"),
            SubscriptionType::Vps => write!(f, "VPS"),
            SubscriptionType::App => write!(f, "App"),
        }
    }
}

/// Line item within a subscription
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionLineItem {
    pub id: u64,
    pub subscription_id: u64,
    /// Discriminant indicating which product table owns this line item
    pub subscription_type: SubscriptionType,
    pub name: String,
    pub description: Option<String>,
    pub amount: u64,
    pub setup_amount: u64,
    /// Upgrade bookkeeping for this line item, serialized as JSON.
    ///
    /// This stores upgrade configuration only (e.g. `UpgradeConfig` —
    /// `new_cpu` / `new_memory` / `new_disk`) recorded when a VM's specs are
    /// changed. It is NOT a link to the resource this line item bills for:
    /// the linked resource is resolved from [`SubscriptionType`] via the
    /// back-reference tables (`vm.subscription_line_item_id`,
    /// `ip_range_subscription.subscription_line_item_id`, ...), never by
    /// parsing this column.
    pub configuration: Option<serde_json::Value>,
}

/// Subscription payment
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionPayment {
    pub id: Vec<u8>,
    pub subscription_id: u64,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub payment_method: PaymentMethod,
    pub payment_type: SubscriptionPaymentType,
    pub external_data: EncryptedString,
    pub external_id: Option<String>,
    pub is_paid: bool,
    pub rate: f32,
    /// Number of seconds this payment adds to subscription expiry
    pub time_value: Option<u64>,
    /// JSON metadata (e.g. upgrade parameters)
    pub metadata: Option<serde_json::Value>,
    pub tax: u64,
    pub processing_fee: u64,
    /// Timestamp when the payment was completed
    pub paid_at: Option<DateTime<Utc>>,
    /// Summary VAT rate (%) when the breakdown is uniform; `None` if the payment
    /// mixes rates across line items (see `tax_breakdown`).
    #[sqlx(default)]
    pub tax_rate: Option<f32>,
    /// Summary place-of-supply country (ISO alpha-3) when uniform; `None` if mixed.
    #[sqlx(default)]
    pub tax_country_code: Option<String>,
    /// Summary treatment (see `TaxTreatment`) when uniform; `None` if mixed.
    #[sqlx(default)]
    pub tax_treatment: Option<String>,
    /// Evidence used for the determination (declared/geo country, VAT number),
    /// as JSON, frozen at sale time. Uniform per payment (one customer).
    #[sqlx(default)]
    pub tax_evidence: Option<serde_json::Value>,
    /// Authoritative per-line-item VAT breakdown (JSON array), frozen at sale
    /// time. Losslessly records payments that mix rates/treatments.
    #[sqlx(default)]
    pub tax_breakdown: Option<serde_json::Value>,
}

/// Subscription payment with company info (for admin views and time-series reporting)
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionPaymentWithCompany {
    pub id: Vec<u8>,
    pub subscription_id: u64,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub payment_method: PaymentMethod,
    pub payment_type: SubscriptionPaymentType,
    pub external_data: EncryptedString,
    pub external_id: Option<String>,
    pub is_paid: bool,
    pub rate: f32,
    /// Number of seconds this payment adds to subscription expiry
    pub time_value: Option<u64>,
    /// JSON metadata (e.g. upgrade parameters)
    pub metadata: Option<serde_json::Value>,
    pub tax: u64,
    pub processing_fee: u64,
    /// Timestamp when the payment was completed
    pub paid_at: Option<DateTime<Utc>>,
    /// Summary VAT rate (%) when uniform; `None` if mixed (see `tax_breakdown`).
    #[sqlx(default)]
    pub tax_rate: Option<f32>,
    /// Summary place-of-supply country (ISO alpha-3) when uniform; `None` if mixed.
    #[sqlx(default)]
    pub tax_country_code: Option<String>,
    /// Summary treatment (see `TaxTreatment`) when uniform; `None` if mixed.
    #[sqlx(default)]
    pub tax_treatment: Option<String>,
    /// Evidence used for the determination, as JSON, frozen at sale time.
    #[sqlx(default)]
    pub tax_evidence: Option<serde_json::Value>,
    /// Authoritative per-line-item VAT breakdown (JSON array), frozen at sale time.
    #[sqlx(default)]
    pub tax_breakdown: Option<serde_json::Value>,
    // Company information
    pub company_id: u64,
    pub company_name: String,
    pub company_base_currency: String,
    // VM information (NULL for non-VM subscriptions)
    pub vm_id: Option<u64>,
    // Host information
    pub host_id: Option<u64>,
    pub host_name: Option<String>,
    // Region information
    pub region_id: Option<u64>,
    pub region_name: Option<String>,
}

/// Internet Registry - Regional Internet Registry
#[derive(Clone, Copy, Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum InternetRegistry {
    ARIN = 0,    // American Registry for Internet Numbers
    RIPE = 1,    // Réseaux IP Européens Network Coordination Centre
    APNIC = 2,   // Asia-Pacific Network Information Centre
    LACNIC = 3,  // Latin America and Caribbean Network Information Centre
    AFRINIC = 4, // African Network Information Centre
}

impl Display for InternetRegistry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InternetRegistry::ARIN => write!(f, "ARIN"),
            InternetRegistry::RIPE => write!(f, "RIPE"),
            InternetRegistry::APNIC => write!(f, "APNIC"),
            InternetRegistry::LACNIC => write!(f, "LACNIC"),
            InternetRegistry::AFRINIC => write!(f, "AFRINIC"),
        }
    }
}

impl InternetRegistry {
    /// Get the minimum IPv4 prefix size that can be announced in BGP for this RIR
    /// Based on industry-standard minimum announcement sizes
    pub fn min_ipv4_prefix_size(&self) -> u16 {
        match self {
            InternetRegistry::ARIN => 24,    // /24 minimum
            InternetRegistry::RIPE => 24,    // /24 minimum
            InternetRegistry::APNIC => 24,   // /24 minimum
            InternetRegistry::LACNIC => 24,  // /24 minimum
            InternetRegistry::AFRINIC => 24, // /24 minimum
        }
    }

    /// Get the minimum IPv6 prefix size that can be announced in BGP for this RIR
    /// Based on industry-standard minimum announcement sizes
    pub fn min_ipv6_prefix_size(&self) -> u16 {
        match self {
            InternetRegistry::ARIN => 48, // /48 minimum (though /32 is more common for allocations)
            InternetRegistry::RIPE => 48, // /48 minimum
            InternetRegistry::APNIC => 48, // /48 minimum
            InternetRegistry::LACNIC => 48, // /48 minimum
            InternetRegistry::AFRINIC => 48, // /48 minimum
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_distribution_from_str_and_display() {
        let all = [
            ("ubuntu", OsDistribution::Ubuntu, "Ubuntu"),
            ("debian", OsDistribution::Debian, "Debian"),
            ("centos", OsDistribution::CentOS, "CentOs"),
            ("fedora", OsDistribution::Fedora, "Fedora"),
            ("freebsd", OsDistribution::FreeBSD, "FreeBSD"),
            ("opensuse", OsDistribution::OpenSUSE, "OpenSuse"),
            ("archlinux", OsDistribution::ArchLinux, "Arch Linux"),
            (
                "redhatenterprise",
                OsDistribution::RedHatEnterprise,
                "Red Hat Enterprise",
            ),
            ("almalinux", OsDistribution::AlmaLinux, "AlmaLinux"),
            ("rockylinux", OsDistribution::RockyLinux, "Rocky Linux"),
            ("alpine", OsDistribution::Alpine, "Alpine"),
            ("nixos", OsDistribution::NixOS, "NixOS"),
            ("openbsd", OsDistribution::OpenBSD, "OpenBSD"),
            ("netbsd", OsDistribution::NetBSD, "NetBSD"),
            ("gentoo", OsDistribution::Gentoo, "Gentoo"),
            ("voidlinux", OsDistribution::VoidLinux, "Void Linux"),
        ];
        for (s, d, display) in all {
            assert_eq!(OsDistribution::from_str(s).unwrap(), d);
            // Case-insensitive
            assert_eq!(OsDistribution::from_str(&s.to_uppercase()).unwrap(), d);
            assert_eq!(d.to_string(), display);
        }
        assert!(OsDistribution::from_str("templeos").is_err());
    }

    fn os_image(url: &str) -> VmOsImage {
        VmOsImage {
            id: 1,
            distribution: OsDistribution::Ubuntu,
            flavour: "server".to_string(),
            version: "24.04".to_string(),
            enabled: true,
            release_date: Utc::now(),
            url: url.to_string(),
            cpu_arch: CpuArch::X86_64,
            default_username: None,
            sha2: None,
            sha2_url: None,
        }
    }

    #[test]
    fn test_os_image_compression_and_filename() {
        // Uncompressed images
        let img = os_image("https://example.com/images/foo.qcow2");
        assert_eq!(img.compression(), None);
        assert_eq!(img.url_filename().unwrap(), "foo.qcow2");
        assert_eq!(img.filename().unwrap(), "foo.img");

        let img = os_image("https://example.com/images/foo.img");
        assert_eq!(img.compression(), None);
        assert_eq!(img.filename().unwrap(), "foo.img");

        // Compressed images: every supported extension is detected and stripped
        for ext in OS_IMAGE_COMPRESSION_EXTENSIONS {
            let img = os_image(&format!("https://example.com/images/foo.qcow2.{ext}"));
            assert_eq!(img.compression().as_deref(), Some(*ext));
            assert_eq!(img.url_filename().unwrap(), format!("foo.qcow2.{ext}"));
            assert_eq!(img.filename().unwrap(), "foo.img");
        }

        // Uppercase extension is normalised
        let img = os_image("https://example.com/images/foo.qcow2.XZ");
        assert_eq!(img.compression().as_deref(), Some("xz"));
        assert_eq!(img.filename().unwrap(), "foo.img");

        // Unknown extension is not treated as compression
        let img = os_image("https://example.com/images/foo.raw");
        assert_eq!(img.compression(), None);
        assert_eq!(img.filename().unwrap(), "foo.img");
    }

    #[test]
    fn test_referral_payout_mode_roundtrip() {
        for (s, m) in [
            ("lightning_address", ReferralPayoutMode::LightningAddress),
            ("nwc", ReferralPayoutMode::Nwc),
            ("account_credit", ReferralPayoutMode::AccountCredit),
            ("on_chain", ReferralPayoutMode::OnChain),
        ] {
            assert_eq!(ReferralPayoutMode::from_str(s).unwrap(), m);
            assert_eq!(m.to_string(), s);
        }
        // Aliases + case-insensitivity
        assert_eq!(
            ReferralPayoutMode::from_str("NWC").unwrap(),
            ReferralPayoutMode::Nwc
        );
        assert_eq!(
            ReferralPayoutMode::from_str("onchain").unwrap(),
            ReferralPayoutMode::OnChain
        );
        assert_eq!(
            ReferralPayoutMode::from_str("lightning").unwrap(),
            ReferralPayoutMode::LightningAddress
        );
        assert!(ReferralPayoutMode::from_str("bogus").is_err());
        assert_eq!(
            ReferralPayoutMode::default(),
            ReferralPayoutMode::LightningAddress
        );
    }

    #[test]
    fn test_referral_cost_usage_commission() {
        let mut u = ReferralCostUsage {
            vm_id: 1,
            ref_code: "X".to_string(),
            created: Utc::now(),
            amount: 10_000,
            currency: "EUR".to_string(),
            rate: 1.0,
            base_currency: "EUR".to_string(),
            effective_rate: 10.0,
        };
        // 10% of 10_000 = 1_000
        assert_eq!(u.commission(), 1_000);
        // 0% disables commission
        u.effective_rate = 0.0;
        assert_eq!(u.commission(), 0);
        // Floored (2.5% of 101 = 2.525 -> 2)
        u.amount = 101;
        u.effective_rate = 2.5;
        assert_eq!(u.commission(), 2);
    }

    #[test]
    fn test_user_payment_method_is_expired() {
        let mut pm = UserPaymentMethod {
            exp_year: Some(2029),
            exp_month: Some(12),
            ..Default::default()
        };
        // Before expiry
        assert!(!pm.is_expired(2029, 11));
        // Same month is not yet expired
        assert!(!pm.is_expired(2029, 12));
        // After expiry month
        assert!(pm.is_expired(2030, 1));
        assert!(pm.is_expired(2029, 12) == false);
        // Earlier year
        assert!(!pm.is_expired(2028, 12));
        // Missing expiry data -> never expired
        pm.exp_year = None;
        assert!(!pm.is_expired(2030, 1));
        pm.exp_year = Some(2029);
        pm.exp_month = None;
        assert!(!pm.is_expired(2030, 1));
    }

    #[test]
    fn test_internet_registry_min_prefix_sizes() {
        // Test that all RIRs return correct minimum prefix sizes
        assert_eq!(InternetRegistry::ARIN.min_ipv4_prefix_size(), 24);
        assert_eq!(InternetRegistry::RIPE.min_ipv4_prefix_size(), 24);
        assert_eq!(InternetRegistry::APNIC.min_ipv4_prefix_size(), 24);
        assert_eq!(InternetRegistry::LACNIC.min_ipv4_prefix_size(), 24);
        assert_eq!(InternetRegistry::AFRINIC.min_ipv4_prefix_size(), 24);

        assert_eq!(InternetRegistry::ARIN.min_ipv6_prefix_size(), 48);
        assert_eq!(InternetRegistry::RIPE.min_ipv6_prefix_size(), 48);
        assert_eq!(InternetRegistry::APNIC.min_ipv6_prefix_size(), 48);
        assert_eq!(InternetRegistry::LACNIC.min_ipv6_prefix_size(), 48);
        assert_eq!(InternetRegistry::AFRINIC.min_ipv6_prefix_size(), 48);
    }

    #[test]
    fn test_admin_resource_dns_server_roundtrip() {
        assert_eq!(
            "dns_server".parse::<AdminResource>().unwrap(),
            AdminResource::DnsServer
        );
        assert_eq!(AdminResource::DnsServer.to_string(), "dns_server");
        assert_eq!(
            AdminResource::try_from(22u16).unwrap(),
            AdminResource::DnsServer
        );
        assert!(AdminResource::all().contains(&AdminResource::DnsServer));
    }

    #[test]
    fn test_admin_resource_user_payment_method_roundtrip() {
        assert_eq!(
            "user_payment_method".parse::<AdminResource>().unwrap(),
            AdminResource::UserPaymentMethod
        );
        assert_eq!(
            AdminResource::UserPaymentMethod.to_string(),
            "user_payment_method"
        );
        assert_eq!(
            AdminResource::try_from(23u16).unwrap(),
            AdminResource::UserPaymentMethod
        );
        assert!(AdminResource::all().contains(&AdminResource::UserPaymentMethod));
    }

    #[test]
    fn test_admin_resource_cost_roundtrip() {
        assert_eq!(
            "resource_cost".parse::<AdminResource>().unwrap(),
            AdminResource::ResourceCost
        );
        assert_eq!(AdminResource::ResourceCost.to_string(), "resource_cost");
        assert_eq!(
            AdminResource::try_from(24u16).unwrap(),
            AdminResource::ResourceCost
        );
        assert!(AdminResource::all().contains(&AdminResource::ResourceCost));
    }

    #[test]
    fn test_admin_resource_referral_roundtrip() {
        assert_eq!(
            "referral".parse::<AdminResource>().unwrap(),
            AdminResource::Referral
        );
        assert_eq!(AdminResource::Referral.to_string(), "referral");
        assert_eq!(
            AdminResource::try_from(25u16).unwrap(),
            AdminResource::Referral
        );
        assert!(AdminResource::all().contains(&AdminResource::Referral));
    }

    #[test]
    fn test_cost_type_and_resource_type_roundtrip() {
        assert_eq!(
            "vm_host".parse::<CostResourceType>().unwrap(),
            CostResourceType::VmHost
        );
        assert_eq!(
            "ip_range".parse::<CostResourceType>().unwrap(),
            CostResourceType::IpRange
        );
        assert_eq!(CostResourceType::IpRange.to_string(), "ip_range");
        assert_eq!(
            "generic".parse::<CostResourceType>().unwrap(),
            CostResourceType::Generic
        );
        assert_eq!(CostResourceType::Generic.to_string(), "generic");
        assert_eq!(
            "recurring".parse::<CostType>().unwrap(),
            CostType::Recurring
        );
        assert_eq!("one_time".parse::<CostType>().unwrap(), CostType::OneTime);
        assert_eq!(CostType::OneTime.to_string(), "one_time");
    }

    #[test]
    fn test_cpu_mfg_from_str() {
        assert_eq!("intel".parse::<CpuMfg>().unwrap(), CpuMfg::Intel);
        assert_eq!("Intel".parse::<CpuMfg>().unwrap(), CpuMfg::Intel);
        assert_eq!("INTEL".parse::<CpuMfg>().unwrap(), CpuMfg::Intel);
        assert_eq!("amd".parse::<CpuMfg>().unwrap(), CpuMfg::Amd);
        assert_eq!("AMD".parse::<CpuMfg>().unwrap(), CpuMfg::Amd);
        assert_eq!("apple".parse::<CpuMfg>().unwrap(), CpuMfg::Apple);
        assert_eq!("nvidia".parse::<CpuMfg>().unwrap(), CpuMfg::Nvidia);
        assert_eq!("unknown".parse::<CpuMfg>().unwrap(), CpuMfg::Unknown);
        assert!("invalid".parse::<CpuMfg>().is_err());
        assert!("".parse::<CpuMfg>().is_err());
    }

    #[test]
    fn test_admin_action_bulk_update_roundtrip() {
        // Display / FromStr / TryFrom round-trip for the new bulk_update action
        assert_eq!(AdminAction::BulkUpdate.to_string(), "bulk_update");
        assert_eq!(
            "bulk_update".parse::<AdminAction>().unwrap(),
            AdminAction::BulkUpdate
        );
        assert_eq!(
            "bulk".parse::<AdminAction>().unwrap(),
            AdminAction::BulkUpdate
        );
        assert_eq!(
            AdminAction::try_from(4u16).unwrap(),
            AdminAction::BulkUpdate
        );
        assert_eq!(AdminAction::BulkUpdate as u16, 4);
        assert!(AdminAction::all().contains(&AdminAction::BulkUpdate));
    }

    #[test]
    fn test_cpu_arch_from_str() {
        assert_eq!("x86_64".parse::<CpuArch>().unwrap(), CpuArch::X86_64);
        assert_eq!("X86_64".parse::<CpuArch>().unwrap(), CpuArch::X86_64);
        assert_eq!("x86-64".parse::<CpuArch>().unwrap(), CpuArch::X86_64);
        assert_eq!("amd64".parse::<CpuArch>().unwrap(), CpuArch::X86_64);
        assert_eq!("arm64".parse::<CpuArch>().unwrap(), CpuArch::ARM64);
        assert_eq!("ARM64".parse::<CpuArch>().unwrap(), CpuArch::ARM64);
        assert_eq!("aarch64".parse::<CpuArch>().unwrap(), CpuArch::ARM64);
        assert_eq!("unknown".parse::<CpuArch>().unwrap(), CpuArch::Unknown);
        assert!("invalid".parse::<CpuArch>().is_err());
        assert!("".parse::<CpuArch>().is_err());
    }

    #[test]
    fn test_cpu_mfg_display_roundtrip() {
        for mfg in [
            CpuMfg::Unknown,
            CpuMfg::Intel,
            CpuMfg::Amd,
            CpuMfg::Apple,
            CpuMfg::Nvidia,
        ] {
            let s = mfg.to_string();
            let parsed: CpuMfg = s.parse().unwrap();
            assert_eq!(parsed, mfg);
        }
    }

    #[test]
    fn test_cpu_arch_display_roundtrip() {
        for arch in [CpuArch::Unknown, CpuArch::X86_64, CpuArch::ARM64] {
            let s = arch.to_string();
            let parsed: CpuArch = s.parse().unwrap();
            assert_eq!(parsed, arch);
        }
    }

    #[test]
    fn test_payment_method_roundtrip() {
        for (s, m) in [
            ("lightning", PaymentMethod::Lightning),
            ("revolut", PaymentMethod::Revolut),
            ("paypal", PaymentMethod::Paypal),
            ("stripe", PaymentMethod::Stripe),
            ("onchain", PaymentMethod::OnChain),
        ] {
            assert_eq!(PaymentMethod::from_str(s).unwrap(), m);
        }
        assert_eq!(PaymentMethod::OnChain.to_string(), "OnChain");
        assert!(PaymentMethod::from_str("bogus").is_err());
    }

    #[test]
    fn test_provider_config_onchain() {
        let config = ProviderConfig::OnChain(OnChainProviderConfig {
            url: "https://localhost:10009".to_string(),
            cert_path: "/tls.cert".into(),
            macaroon_path: "/admin.macaroon".into(),
            address_type: OnChainAddressType::TaprootPubkey,
            account: Some("deposits".to_string()),
            min_confirmations: 3,
        });
        assert_eq!(config.provider_type(), "onchain");
        assert_eq!(config.payment_method(), PaymentMethod::OnChain);
        assert!(config.as_onchain().is_some());
        assert!(config.as_lnd().is_none());
        assert!(
            ProviderConfig::Lnd(LndConfig {
                url: "".to_string(),
                cert_path: "".into(),
                macaroon_path: "".into(),
            })
            .as_onchain()
            .is_none()
        );

        // serde round-trip via PaymentMethodConfig helpers
        let mut pmc = PaymentMethodConfig::new_with_config(
            1,
            PaymentMethod::OnChain,
            "onchain".to_string(),
            true,
            config,
        );
        assert_eq!(pmc.provider_type, "onchain");
        let parsed = pmc.get_provider_config().expect("config round-trips");
        let oc = parsed.as_onchain().unwrap();
        assert_eq!(oc.url, "https://localhost:10009");
        assert_eq!(oc.address_type, OnChainAddressType::TaprootPubkey);
        assert_eq!(oc.account.as_deref(), Some("deposits"));
        assert_eq!(oc.min_confirmations, 3);
        pmc.set_provider_config(parsed);
        assert_eq!(pmc.provider_type, "onchain");
    }

    #[test]
    fn test_onchain_provider_config_defaults() {
        // Old configs without the new fields deserialize with defaults
        let json = serde_json::json!({
            "type": "onchain",
            "url": "https://localhost:10009",
            "cert_path": "/tls.cert",
            "macaroon_path": "/admin.macaroon"
        });
        let cfg: ProviderConfig = serde_json::from_value(json).unwrap();
        let oc = cfg.as_onchain().unwrap();
        assert_eq!(oc.address_type, OnChainAddressType::WitnessPubkeyHash);
        assert_eq!(oc.account, None);
        assert_eq!(oc.min_confirmations, 1);
    }
}

/// Available IP Space - Inventory of IP ranges available for sale
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct AvailableIpSpace {
    pub id: u64,
    /// Company that owns this IP space inventory
    pub company_id: u64,
    pub cidr: String,
    pub min_prefix_size: u16,
    pub max_prefix_size: u16,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub registry: InternetRegistry,
    pub external_id: Option<String>,
    pub is_available: bool,
    pub is_reserved: bool,
    pub metadata: Option<serde_json::Value>,
}

/// IP Space Pricing - Pricing for different prefix sizes from an IP block
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct IpSpacePricing {
    pub id: u64,
    pub available_ip_space_id: u64,
    pub prefix_size: u16,
    pub price_per_month: u64,
    pub currency: String,
    pub setup_fee: u64,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

/// IP Range Subscription - Stores IP ranges sold to users via subscriptions
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct IpRangeSubscription {
    pub id: u64,
    pub subscription_line_item_id: u64,
    pub available_ip_space_id: u64,
    pub created: DateTime<Utc>,
    pub cidr: String,
    /// The origin AS number the customer announces this prefix from. Mutable
    /// operational state (a re-home re-issues the route object + ROA); `None`
    /// until the customer configures it, in which case no registry objects
    /// exist yet.
    pub origin_asn: Option<u32>,
    pub is_active: bool,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

/// Lifecycle status of a sponsored ASN request.
#[derive(Clone, Copy, Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq, Default)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum AsnSubscriptionStatus {
    /// Sponsorship request filed with the RIR, awaiting assignment.
    #[default]
    Requested = 0,
    /// The RIR assigned the AS number.
    Assigned = 1,
    /// The request failed or was withdrawn.
    Failed = 2,
}

impl Display for AsnSubscriptionStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AsnSubscriptionStatus::Requested => write!(f, "requested"),
            AsnSubscriptionStatus::Assigned => write!(f, "assigned"),
            AsnSubscriptionStatus::Failed => write!(f, "failed"),
        }
    }
}

impl FromStr for AsnSubscriptionStatus {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "requested" | "pending" => Ok(AsnSubscriptionStatus::Requested),
            "assigned" | "active" => Ok(AsnSubscriptionStatus::Assigned),
            "failed" | "withdrawn" => Ok(AsnSubscriptionStatus::Failed),
            _ => Err(anyhow!("unknown ASN subscription status: {}", s)),
        }
    }
}

/// ASN Subscription - a sponsored AS number sold to a user via a subscription.
///
/// Unlike an IP range, the AS number is a unique registry resource assigned by
/// the RIR (an async, admin-in-the-loop process), so `asn` is `None` until
/// assigned and `status` tracks the request lifecycle.
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct AsnSubscription {
    pub id: u64,
    pub subscription_line_item_id: u64,
    /// Registry the ASN is (to be) sponsored under.
    pub registry: InternetRegistry,
    /// The assigned AS number; `None` until the RIR assigns it.
    pub asn: Option<u32>,
    pub status: AsnSubscriptionStatus,
    pub created: DateTime<Utc>,
    /// When the RIR assigned the number (`None` while pending).
    pub assigned_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub ended_at: Option<DateTime<Utc>>,
    /// Primary key of the created `aut-num` whois object, once created.
    pub aut_num_ref: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Lightning provider configuration - LND
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LndConfig {
    /// LND REST API URL
    pub url: String,
    /// Path to TLS certificate
    pub cert_path: PathBuf,
    /// Path to macaroon file
    pub macaroon_path: PathBuf,
}

/// Lightning provider configuration - Bitvora
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitvoraConfig {
    /// API token
    pub token: String,
    /// Webhook secret for verifying callbacks
    pub webhook_secret: String,
}

/// Revolut provider configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevolutProviderConfig {
    /// Revolut API URL
    pub url: String,
    /// API token
    pub token: String,
    /// API version string
    pub api_version: String,
    /// Public key for client-side integration
    pub public_key: String,
    /// Webhook signing secret (populated after webhook registration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
}

/// Stripe provider configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StripeProviderConfig {
    /// Secret API key
    pub secret_key: String,
    /// Publishable key for client-side
    pub publishable_key: String,
    /// Webhook secret for verifying callbacks
    pub webhook_secret: String,
}

/// On-chain receive-address type (mirrors LND's supported families)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnChainAddressType {
    /// Pay-to-witness-public-key-hash (`p2wkh`, bech32)
    #[default]
    WitnessPubkeyHash,
    /// Nested pay-to-witness-public-key-hash (`np2wkh`, base58)
    NestedPubkeyHash,
    /// Pay-to-taproot (`p2tr`, bech32m)
    TaprootPubkey,
}

/// On-chain Bitcoin provider configuration (LND wallet backend)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnChainProviderConfig {
    /// LND gRPC API URL
    pub url: String,
    /// Path to TLS certificate
    pub cert_path: PathBuf,
    /// Path to macaroon file
    pub macaroon_path: PathBuf,
    /// Type of receive address to derive
    #[serde(default)]
    pub address_type: OnChainAddressType,
    /// Optional wallet account name (`None` uses the default account)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Confirmations required before a deposit is settled
    #[serde(default = "default_min_confirmations")]
    pub min_confirmations: u32,
}

fn default_min_confirmations() -> u32 {
    1
}

/// PayPal provider configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaypalProviderConfig {
    /// Client ID
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// Mode: "sandbox" or "live"
    pub mode: String,
}

/// Typed provider configuration enum
/// Wraps all supported payment provider configurations
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfig {
    /// LND Lightning Network Daemon configuration
    Lnd(LndConfig),
    /// Bitvora Lightning provider configuration
    Bitvora(BitvoraConfig),
    /// Revolut fiat payment configuration
    Revolut(RevolutProviderConfig),
    /// Stripe fiat payment configuration
    Stripe(StripeProviderConfig),
    /// PayPal fiat payment configuration
    Paypal(PaypalProviderConfig),
    /// On-chain Bitcoin payment configuration (LND wallet backend)
    #[serde(rename = "onchain")]
    OnChain(OnChainProviderConfig),
}

impl ProviderConfig {
    /// Get the provider type string for this config
    pub fn provider_type(&self) -> &'static str {
        match self {
            ProviderConfig::Lnd(_) => "lnd",
            ProviderConfig::Bitvora(_) => "bitvora",
            ProviderConfig::Revolut(_) => "revolut",
            ProviderConfig::Stripe(_) => "stripe",
            ProviderConfig::Paypal(_) => "paypal",
            ProviderConfig::OnChain(_) => "onchain",
        }
    }

    /// Get the payment method for this provider config
    pub fn payment_method(&self) -> PaymentMethod {
        match self {
            ProviderConfig::Lnd(_) | ProviderConfig::Bitvora(_) => PaymentMethod::Lightning,
            ProviderConfig::Revolut(_) => PaymentMethod::Revolut,
            ProviderConfig::Stripe(_) => PaymentMethod::Stripe,
            ProviderConfig::Paypal(_) => PaymentMethod::Paypal,
            ProviderConfig::OnChain(_) => PaymentMethod::OnChain,
        }
    }

    /// Get LND config if this is an LND provider
    pub fn as_lnd(&self) -> Option<&LndConfig> {
        match self {
            ProviderConfig::Lnd(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Get Bitvora config if this is a Bitvora provider
    pub fn as_bitvora(&self) -> Option<&BitvoraConfig> {
        match self {
            ProviderConfig::Bitvora(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Get Revolut config if this is a Revolut provider
    pub fn as_revolut(&self) -> Option<&RevolutProviderConfig> {
        match self {
            ProviderConfig::Revolut(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Get Stripe config if this is a Stripe provider
    pub fn as_stripe(&self) -> Option<&StripeProviderConfig> {
        match self {
            ProviderConfig::Stripe(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Get PayPal config if this is a PayPal provider
    pub fn as_paypal(&self) -> Option<&PaypalProviderConfig> {
        match self {
            ProviderConfig::Paypal(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Get on-chain config if this is an on-chain provider
    pub fn as_onchain(&self) -> Option<&OnChainProviderConfig> {
        match self {
            ProviderConfig::OnChain(cfg) => Some(cfg),
            _ => None,
        }
    }
}

/// Payment method configuration stored in database
/// Replaces YAML config for payment providers
#[derive(FromRow, Clone, Debug)]
pub struct PaymentMethodConfig {
    /// Unique id of this configuration
    pub id: u64,
    /// Company that owns this payment method configuration
    pub company_id: u64,
    /// Payment method type (Lightning, Revolut, etc.)
    pub payment_method: PaymentMethod,
    /// Display name for this configuration
    pub name: String,
    /// Whether this payment method is enabled
    pub enabled: bool,
    /// Provider type string (e.g., "lnd", "bitvora", "revolut")
    pub provider_type: String,
    /// JSON configuration for the provider
    pub config: Option<serde_json::Value>,
    /// Processing fee percentage rate (e.g., 1.0 for 1%)
    pub processing_fee_rate: Option<f32>,
    /// Processing fee base amount in smallest currency unit
    pub processing_fee_base: Option<u64>,
    /// Currency for the processing fee base
    pub processing_fee_currency: Option<String>,
    /// Minimum processable amount in the smallest unit of `min_amount_currency`
    /// (cents for fiat, millisats for BTC). `None` (or 0) means no minimum.
    /// Payments whose gross total is below this are rejected for this method.
    pub min_amount: Option<u64>,
    /// Currency for `min_amount`
    pub min_amount_currency: Option<String>,
    /// Supported currency codes (e.g., "EUR", "USD", "BTC")
    /// Empty means use default currencies based on payment method type
    pub supported_currencies: CommaSeparated<String>,
    /// Created timestamp
    pub created: DateTime<Utc>,
    /// Last modified timestamp
    pub modified: DateTime<Utc>,
}

impl PaymentMethodConfig {
    /// Get the typed provider configuration
    /// Returns None if config is None or deserialization fails
    pub fn get_provider_config(&self) -> Option<ProviderConfig> {
        self.config
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Set the provider configuration from a typed config
    /// Updates both the config JSON and provider_type field
    pub fn set_provider_config(&mut self, provider_config: ProviderConfig) {
        self.provider_type = provider_config.provider_type().to_string();
        self.config = serde_json::to_value(&provider_config).ok();
    }

    /// Create a new PaymentMethodConfig with a typed provider configuration
    pub fn new_with_config(
        company_id: u64,
        payment_method: PaymentMethod,
        name: String,
        enabled: bool,
        provider_config: ProviderConfig,
    ) -> Self {
        let provider_type = provider_config.provider_type().to_string();
        let config = serde_json::to_value(&provider_config).ok();
        Self {
            id: 0,
            company_id,
            payment_method,
            name,
            enabled,
            provider_type,
            config,
            processing_fee_rate: None,
            processing_fee_base: None,
            processing_fee_currency: None,
            min_amount: None,
            min_amount_currency: None,
            supported_currencies: CommaSeparated::default(),
            created: Utc::now(),
            modified: Utc::now(),
        }
    }
}

/// A predefined managed application in the catalog.
///
/// Each app is defined by a **docker-compose-style YAML** blob (`compose`) that
/// describes the container image(s), ports, environment and volumes. The
/// customer UI renders forms from that spec, and `lnvps_operator` translates it
/// (merged with a deployment's chosen config) into Kubernetes objects. Apps are
/// billed through the subscription engine using the inline pricing fields
/// (`amount`/`currency`/`interval_*`, matching [`VmCostPlan`]).
#[derive(FromRow, Clone, Debug)]
pub struct App {
    pub id: u64,
    /// URL/DNS-safe slug (e.g. `nostr-relay`); unique.
    pub name: String,
    /// Human-friendly catalog name.
    pub display_name: String,
    pub description: Option<String>,
    /// Optional icon/logo URL for the catalog UI.
    pub icon: Option<String>,
    /// Docker-compose-style YAML defining the app (image, ports, env, volumes).
    pub compose: String,
    /// Recurring price in the smallest currency unit (cents / millisats).
    pub amount: u64,
    pub currency: String,
    /// Billing interval, e.g. `1` `Month`.
    pub interval_amount: u64,
    pub interval_type: IntervalType,
    /// One-off setup fee in the smallest currency unit (0 = none).
    pub setup_amount: u64,
    /// Whether the app is offered in the catalog.
    pub enabled: bool,
    /// Resource footprint computed from the compose (Σ service CPU requests, in
    /// millicores). Denormalized for cheap cluster-capacity accounting.
    #[sqlx(default)]
    pub cpu_milli: u64,
    /// Memory footprint in bytes.
    #[sqlx(default)]
    pub memory_bytes: u64,
    /// Persistent storage footprint in bytes.
    #[sqlx(default)]
    pub storage_bytes: u64,
    pub created: DateTime<Utc>,
}

/// A Kubernetes cluster where apps can be deployed.
///
/// Linked to a [`Region`] so location, company, tax and currency resolve
/// exactly like VMs (`region.company_id`). The `lnvps_operator` instance that
/// runs inside a cluster is configured with its own cluster id and reconciles
/// only that cluster's deployments — no kube credentials are stored in the DB.
#[derive(FromRow, Clone, Debug)]
pub struct AppCluster {
    pub id: u64,
    pub name: String,
    /// Region this cluster belongs to (drives company / tax / currency).
    pub region_id: u64,
    /// Wildcard base domain for ingress hostnames on this cluster; a
    /// deployment's host is `"{deployment.name}.{ingress_domain}"`.
    pub ingress_domain: String,
    pub enabled: bool,
    /// Static total CPU capacity (millicores) available for app deployments.
    #[sqlx(default)]
    pub capacity_cpu_milli: u64,
    /// Static total memory capacity (bytes).
    #[sqlx(default)]
    pub capacity_memory_bytes: u64,
    /// Static total persistent-storage capacity (bytes).
    #[sqlx(default)]
    pub capacity_storage_bytes: u64,
    pub created: DateTime<Utc>,
}

/// Desired run state of a deployment, set by the customer and honoured by the
/// operator (scale to 0 replicas when `Stopped`).
#[derive(Clone, Copy, Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq, Default)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum AppDeploymentDesiredState {
    #[default]
    Running = 0,
    Stopped = 1,
}

impl Display for AppDeploymentDesiredState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AppDeploymentDesiredState::Running => write!(f, "running"),
            AppDeploymentDesiredState::Stopped => write!(f, "stopped"),
        }
    }
}

/// Observed status of a deployment, written back by the operator as it
/// reconciles the Kubernetes resources.
#[derive(Clone, Copy, Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq, Default)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum AppDeploymentStatus {
    /// Created in the DB but not yet reconciled / not yet ready.
    #[default]
    Pending = 0,
    /// Reconciled and the workload is running.
    Running = 1,
    /// Scaled to zero at the customer's request.
    Stopped = 2,
    /// Reconciliation failed; see `status_message`.
    Error = 3,
    /// Being torn down.
    Deleting = 4,
}

impl Display for AppDeploymentStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AppDeploymentStatus::Pending => write!(f, "pending"),
            AppDeploymentStatus::Running => write!(f, "running"),
            AppDeploymentStatus::Stopped => write!(f, "stopped"),
            AppDeploymentStatus::Error => write!(f, "error"),
            AppDeploymentStatus::Deleting => write!(f, "deleting"),
        }
    }
}

/// A customer's running instance of an [`App`].
///
/// Billed via the subscription engine: `subscription_line_item_id` links to a
/// [`SubscriptionLineItem`] of type [`SubscriptionType::App`], mirroring how
/// `vm.subscription_line_item_id` works. Reconciled into its own Kubernetes
/// namespace (`namespace`) by `lnvps_operator`.
#[derive(FromRow, Clone, Debug)]
pub struct AppDeployment {
    pub id: u64,
    pub user_id: u64,
    /// Catalog app being deployed.
    pub app_id: u64,
    /// Cluster this deployment runs on (drives placement + billing region).
    pub cluster_id: u64,
    /// Billing back-reference (subscription line item of type `App`).
    pub subscription_line_item_id: u64,
    /// User-chosen, DNS-safe instance name (used for the subdomain/host).
    pub name: String,
    /// Dedicated Kubernetes namespace for this deployment (isolation boundary).
    pub namespace: String,
    /// Public ingress hostname once assigned (e.g. `name.apps.lnvps.tld`).
    pub hostname: Option<String>,
    /// Resolved per-deployment configuration (env values etc.), stored as an
    /// encrypted JSON blob so secret values are protected at rest. `None` until
    /// the customer supplies configuration.
    pub config: Option<EncryptedString>,
    /// Desired run state (customer-controlled).
    pub desired_state: AppDeploymentDesiredState,
    /// Observed status (operator-controlled).
    pub status: AppDeploymentStatus,
    /// Optional human-readable status/error detail from the operator.
    pub status_message: Option<String>,
    pub created: DateTime<Utc>,
    /// Soft-delete flag; a deleted deployment is torn down by the operator and
    /// retained only for accounting.
    pub deleted: bool,
}
