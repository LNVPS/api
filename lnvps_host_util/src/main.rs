//! Host CPU detection utility for LNVPS
//!
//! Outputs JSON with cpu_mfg, cpu_arch, and cpu_features that can be used
//! when registering a host with LNVPS.

mod gpu;

#[cfg(target_os = "linux")]
use cros_libva::Display;
#[cfg(target_arch = "x86_64")]
use raw_cpuid::CpuId;
use serde::Serialize;
use std::path::Path;

/// CPU manufacturer
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Variants used conditionally per architecture
pub enum CpuMfg {
    Unknown,
    Intel,
    Amd,
    Apple,
    Nvidia,
    Arm,
}

/// CPU architecture
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Variants used conditionally per architecture
pub enum CpuArch {
    Unknown,
    X86_64,
    Arm64,
}

/// Discrete GPU manufacturer
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Variants used conditionally per platform
pub enum GpuMfg {
    None,
    Nvidia,
    Amd,
}

/// Generic detection result for hardware feature detection
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DetectionResult {
    /// Detection succeeded with features found
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        features: Vec<String>,
    },
    /// Hardware not present or driver not loaded
    NotFound,
    /// Hardware present but initialization/query failed
    #[serde(rename = "error")]
    Error { reason: String },
    /// Not supported on this platform
    Unsupported,
}

impl DetectionResult {
    /// Create a successful result with features
    pub fn ok(features: Vec<String>) -> Self {
        Self::Ok {
            name: None,
            features,
        }
    }

    /// Create a successful result with name and features
    pub fn ok_with_name(name: impl Into<String>, features: Vec<String>) -> Self {
        Self::Ok {
            name: Some(name.into()),
            features,
        }
    }

    /// Create an error result
    pub fn error(reason: impl Into<String>) -> Self {
        Self::Error {
            reason: reason.into(),
        }
    }

    /// Get features if detection was successful
    pub fn features(&self) -> &[String] {
        match self {
            Self::Ok { features, .. } => features,
            _ => &[],
        }
    }

    /// Get name if detection was successful
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Ok { name, .. } => name.as_deref(),
            _ => None,
        }
    }

    /// Check if detection was successful
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }
}

/// Output structure matching LNVPS host registration format
#[derive(Debug, Serialize)]
struct HostInfo {
    cpu_mfg: CpuMfg,
    cpu_arch: CpuArch,
    cpu_features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_model: Option<String>,
    gpu_mfg: GpuMfg,
    #[serde(skip_serializing_if = "Option::is_none")]
    gpu_model: Option<String>,
    gpu_features: Vec<String>,
    /// VA-API (iGPU) detection result
    vaapi: DetectionResult,
    /// NVIDIA NVML detection result
    nvml: DetectionResult,
    /// AMD GPU detection result
    amd: DetectionResult,
}

#[cfg(target_arch = "x86_64")]
fn detect_cpu_mfg() -> CpuMfg {
    let cpuid = CpuId::new();

    if let Some(vendor) = cpuid.get_vendor_info() {
        match vendor.as_str() {
            "GenuineIntel" => CpuMfg::Intel,
            "AuthenticAMD" => CpuMfg::Amd,
            _ => CpuMfg::Unknown,
        }
    } else {
        CpuMfg::Unknown
    }
}

#[cfg(target_arch = "aarch64")]
fn detect_cpu_mfg() -> CpuMfg {
    // On ARM, try to detect from /proc/cpuinfo
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        // Check for Apple Silicon
        if cpuinfo.contains("Apple") {
            return CpuMfg::Apple;
        }
        // Check CPU implementer field
        for line in cpuinfo.lines() {
            if line.starts_with("CPU implementer") {
                if let Some(value) = line.split(':').nth(1) {
                    match value.trim() {
                        "0x41" => return CpuMfg::Arm,    // ARM Ltd
                        "0x4e" => return CpuMfg::Nvidia, // NVIDIA
                        _ => {}
                    }
                }
            }
        }
    }
    CpuMfg::Unknown
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn detect_cpu_mfg() -> CpuMfg {
    CpuMfg::Unknown
}

fn detect_cpu_arch() -> CpuArch {
    #[cfg(target_arch = "x86_64")]
    {
        CpuArch::X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        CpuArch::Arm64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        CpuArch::Unknown
    }
}

#[cfg(target_arch = "x86_64")]
fn detect_cpu_model() -> Option<String> {
    let cpuid = CpuId::new();
    cpuid
        .get_processor_brand_string()
        .map(|b| b.as_str().trim().to_string())
}

#[cfg(target_arch = "aarch64")]
fn detect_cpu_model() -> Option<String> {
    // On ARM, try to get model from /proc/cpuinfo
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("Model") || line.starts_with("Hardware") {
                if let Some(value) = line.split(':').nth(1) {
                    return Some(value.trim().to_string());
                }
            }
        }
    }
    None
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn detect_cpu_model() -> Option<String> {
    None
}

/// Detect x86_64 CPU features
#[cfg(target_arch = "x86_64")]
fn detect_cpu_features() -> Vec<String> {
    let cpuid = CpuId::new();
    let mut features = Vec::new();

    // Check feature flags from CPUID
    if let Some(fi) = cpuid.get_feature_info() {
        // SSE family
        if fi.has_sse() {
            features.push("SSE".to_string());
        }
        if fi.has_sse2() {
            features.push("SSE2".to_string());
        }
        if fi.has_sse3() {
            features.push("SSE3".to_string());
        }
        if fi.has_ssse3() {
            features.push("SSSE3".to_string());
        }
        if fi.has_sse41() {
            features.push("SSE4_1".to_string());
        }
        if fi.has_sse42() {
            features.push("SSE4_2".to_string());
        }

        // AVX (basic)
        if fi.has_avx() {
            features.push("AVX".to_string());
        }

        // FMA
        if fi.has_fma() {
            features.push("FMA".to_string());
        }

        // F16C
        if fi.has_f16c() {
            features.push("F16C".to_string());
        }

        // Crypto
        if fi.has_aesni() {
            features.push("AES".to_string());
        }
        if fi.has_pclmulqdq() {
            features.push("PCLMULQDQ".to_string());
        }

        // Virtualization
        if fi.has_vmx() {
            features.push("VMX".to_string());
        }
    }

    // Extended feature flags (leaf 7)
    if let Some(ef) = cpuid.get_extended_feature_info() {
        // AVX2
        if ef.has_avx2() {
            features.push("AVX2".to_string());
        }

        // AVX-512 family
        if ef.has_avx512f() {
            features.push("AVX512F".to_string());
        }
        if ef.has_avx512vnni() {
            features.push("AVX512VNNI".to_string());
        }
        if ef.has_avx512_bf16() {
            features.push("AVX512BF16".to_string());
        }

        // AVX-VNNI (VEX-encoded, non-AVX-512)
        if ef.has_avx_vnni() {
            features.push("AVXVNNI".to_string());
        }

        // SHA (SHA-1, SHA-256)
        if ef.has_sha() {
            features.push("SHA".to_string());
        }

        // GFNI, VAES, VPCLMULQDQ
        if ef.has_gfni() {
            features.push("GFNI".to_string());
        }
        if ef.has_vaes() {
            features.push("VAES".to_string());
        }
        if ef.has_vpclmulqdq() {
            features.push("VPCLMULQDQ".to_string());
        }

        // RNG (RDSEED)
        if ef.has_rdseed() {
            features.push("RNG".to_string());
        }

        // AMX (Advanced Matrix Extensions)
        if ef.has_amx_tile() {
            features.push("AMX".to_string());
        }

        // SGX
        if ef.has_sgx() {
            features.push("SGX".to_string());
        }
    }

    // SHA512 extensions (CPUID leaf 7, subleaf 1, EAX bit 0)
    // This is newer than what raw-cpuid exposes
    if has_sha512_extensions() {
        features.push("SHA512".to_string());
    }

    // AMD SEV (Secure Encrypted Virtualization)
    if is_sev_enabled() {
        features.push("SEV".to_string());
    }

    // Intel TDX (Trust Domain Extensions)
    if is_tdx_enabled() {
        features.push("TDX".to_string());
    }

    // Check for nested virtualization support
    if is_nested_virt_enabled() {
        features.push("NestedVirt".to_string());
    }

    // Sort for consistent output
    features.sort();
    features
}

/// Detect ARM64 CPU features
#[cfg(target_arch = "aarch64")]
fn detect_cpu_features() -> Vec<String> {
    let mut features = Vec::new();

    // On ARM, we need to read from /proc/cpuinfo or use system registers
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        let has_feature = |name: &str| {
            cpuinfo.lines().any(|line| {
                line.starts_with("Features")
                    && line
                        .split(':')
                        .nth(1)
                        .is_some_and(|f| f.split_whitespace().any(|feat| feat == name))
            })
        };

        // SIMD
        if has_feature("asimd") {
            features.push("NEON".to_string());
        }
        if has_feature("sve") {
            features.push("SVE".to_string());
        }
        if has_feature("sve2") {
            features.push("SVE2".to_string());
        }

        // Crypto
        if has_feature("aes") {
            features.push("AES".to_string());
        }
        if has_feature("sha1") || has_feature("sha2") {
            features.push("SHA".to_string());
        }
        if has_feature("sha512") || has_feature("sha3") {
            features.push("SHA512".to_string());
        }
        if has_feature("pmull") {
            features.push("PCLMULQDQ".to_string());
        }

        // RNG
        if has_feature("rng") {
            features.push("RNG".to_string());
        }

        // SME (Scalable Matrix Extension)
        if has_feature("sme") {
            features.push("SME".to_string());
        }
    }

    // Check for KVM/virtualization support
    if std::path::Path::new("/dev/kvm").exists() {
        features.push("NestedVirt".to_string());
    }

    features.sort();
    features
}

/// Fallback for unsupported architectures
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn detect_cpu_features() -> Vec<String> {
    Vec::new()
}

/// Check for SHA512 extensions via CPUID (leaf 7, subleaf 1, EAX bit 0)
#[cfg(target_arch = "x86_64")]
fn has_sha512_extensions() -> bool {
    // raw-cpuid doesn't expose subleaf 1 directly, so we use inline asm
    // CPUID leaf 7, subleaf 1, EAX bit 0 = SHA512
    let eax: u32;
    unsafe {
        std::arch::asm!(
            "push rbx",       // Save rbx (used by LLVM)
            "cpuid",
            "pop rbx",        // Restore rbx
            inout("eax") 7u32 => eax,
            inout("ecx") 1u32 => _,
            out("edx") _,
            options(nostack),
        );
    }
    // Bit 0 of EAX = SHA512
    (eax & 1) != 0
}

#[cfg(not(target_arch = "x86_64"))]
fn has_sha512_extensions() -> bool {
    false
}

/// Check if AMD SEV is enabled (Linux only)
#[cfg(target_os = "linux")]
fn is_sev_enabled() -> bool {
    // Check if SEV is enabled in KVM
    if let Ok(content) = std::fs::read_to_string("/sys/module/kvm_amd/parameters/sev") {
        if content.trim() == "Y" || content.trim() == "1" {
            return true;
        }
    }
    // Also check for /dev/sev device
    std::path::Path::new("/dev/sev").exists()
}

#[cfg(not(target_os = "linux"))]
fn is_sev_enabled() -> bool {
    false
}

/// Check if Intel TDX is enabled (Linux only)
#[cfg(target_os = "linux")]
fn is_tdx_enabled() -> bool {
    // Check for TDX module loaded
    std::path::Path::new("/sys/module/kvm_intel/parameters/tdx").exists()
        || std::path::Path::new("/dev/tdx_guest").exists()
        || std::path::Path::new("/dev/tdx-guest").exists()
}

#[cfg(not(target_os = "linux"))]
fn is_tdx_enabled() -> bool {
    false
}

/// Check if nested virtualization is enabled (Linux only)
#[cfg(target_os = "linux")]
fn is_nested_virt_enabled() -> bool {
    // Intel
    if let Ok(content) = std::fs::read_to_string("/sys/module/kvm_intel/parameters/nested") {
        if content.trim() == "Y" || content.trim() == "1" {
            return true;
        }
    }
    // AMD
    if let Ok(content) = std::fs::read_to_string("/sys/module/kvm_amd/parameters/nested") {
        if content.trim() == "Y" || content.trim() == "1" {
            return true;
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn is_nested_virt_enabled() -> bool {
    false
}

/// Detect VA-API (iGPU) video encode/decode features
#[cfg(target_os = "linux")]
fn detect_vaapi() -> DetectionResult {
    let mut features = Vec::new();

    // Try to open DRM render nodes
    let render_nodes = [
        "/dev/dri/renderD128",
        "/dev/dri/renderD129",
        "/dev/dri/renderD130",
    ];

    // Check if any render nodes exist
    let any_render_node_exists = render_nodes.iter().any(|node| Path::new(node).exists());
    if !any_render_node_exists {
        return DetectionResult::NotFound;
    }

    let mut any_display_opened = false;

    for node in render_nodes {
        if !Path::new(node).exists() {
            continue;
        }

        let display = match Display::open_drm_display(Path::new(node)) {
            Ok(d) => d,
            Err(_) => continue,
        };

        any_display_opened = true;

        // Query supported profiles and entrypoints
        let profiles = match display.query_config_profiles() {
            Ok(p) => p,
            Err(_) => continue,
        };

        for profile in profiles {
            let entrypoints = match display.query_config_entrypoints(profile) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entrypoint in entrypoints {
                if let Some(feature) = map_vaapi_to_feature(profile, entrypoint as i32) {
                    if !features.contains(&feature) {
                        features.push(feature);
                    }
                }
            }
        }

        // Check for video processing (VPP) support
        if display
            .query_config_entrypoints(cros_libva::VAProfile::VAProfileNone)
            .is_ok_and(|eps| eps.contains(&cros_libva::VAEntrypoint::VAEntrypointVideoProc))
        {
            for f in [
                "VideoScaling",
                "VideoDeinterlace",
                "VideoCSC",
                "VideoComposition",
            ] {
                if !features.contains(&f.to_string()) {
                    features.push(f.to_string());
                }
            }
        }

        // Found a working display with features, no need to check other render nodes
        if !features.is_empty() {
            break;
        }
    }

    if !features.is_empty() {
        DetectionResult::ok(features)
    } else if any_display_opened {
        DetectionResult::error("display opened but no encode/decode features found")
    } else {
        DetectionResult::error("failed to open any render node")
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_vaapi() -> DetectionResult {
    DetectionResult::Unsupported
}

/// Map VA-API profile + entrypoint to CpuFeature name
fn map_vaapi_to_feature(profile: i32, entrypoint: i32) -> Option<String> {
    use cros_libva::VAEntrypoint::*;
    use cros_libva::VAProfile::*;

    let is_encode = entrypoint == VAEntrypointEncSlice as i32
        || entrypoint == VAEntrypointEncSliceLP as i32
        || entrypoint == VAEntrypointEncPicture as i32;
    let is_decode = entrypoint == VAEntrypointVLD as i32;

    // H.264/AVC
    if profile == VAProfileH264Main
        || profile == VAProfileH264High
        || profile == VAProfileH264ConstrainedBaseline
    {
        if is_encode {
            return Some("EncodeH264".to_string());
        } else if is_decode {
            return Some("DecodeH264".to_string());
        }
    }

    // H.265/HEVC
    if profile == VAProfileHEVCMain || profile == VAProfileHEVCMain10 {
        if is_encode {
            return Some("EncodeHEVC".to_string());
        } else if is_decode {
            return Some("DecodeHEVC".to_string());
        }
    }

    // AV1
    if profile == VAProfileAV1Profile0 || profile == VAProfileAV1Profile1 {
        if is_encode {
            return Some("EncodeAV1".to_string());
        } else if is_decode {
            return Some("DecodeAV1".to_string());
        }
    }

    // VP9
    if profile == VAProfileVP9Profile0
        || profile == VAProfileVP9Profile1
        || profile == VAProfileVP9Profile2
        || profile == VAProfileVP9Profile3
    {
        if is_encode {
            return Some("EncodeVP9".to_string());
        } else if is_decode {
            return Some("DecodeVP9".to_string());
        }
    }

    // JPEG
    if profile == VAProfileJPEGBaseline {
        if is_encode {
            return Some("EncodeJPEG".to_string());
        } else if is_decode {
            return Some("DecodeJPEG".to_string());
        }
    }

    // MPEG-2
    if profile == VAProfileMPEG2Simple || profile == VAProfileMPEG2Main {
        if is_decode {
            return Some("DecodeMPEG2".to_string());
        }
    }

    // VC-1
    if profile == VAProfileVC1Simple
        || profile == VAProfileVC1Main
        || profile == VAProfileVC1Advanced
    {
        if is_decode {
            return Some("DecodeVC1".to_string());
        }
    }

    None
}

fn main() {
    // Detect CPU features
    let mut cpu_features = detect_cpu_features();

    // Detect VA-API (iGPU) features - these go into cpu_features
    let vaapi = detect_vaapi();
    cpu_features.extend(vaapi.features().iter().cloned());

    // Sort CPU features for consistent output
    cpu_features.sort();
    cpu_features.dedup();

    // Detect discrete GPU (NVIDIA NVENC/NVDEC, AMD VCN/AMF)
    let mut gpu_info = gpu::detect_gpu();
    gpu_info.features.sort();
    gpu_info.features.dedup();

    let info = HostInfo {
        cpu_mfg: detect_cpu_mfg(),
        cpu_arch: detect_cpu_arch(),
        cpu_features,
        cpu_model: detect_cpu_model(),
        gpu_mfg: gpu_info.mfg,
        gpu_model: gpu_info.model,
        gpu_features: gpu_info.features,
        vaapi,
        nvml: gpu_info.nvml,
        amd: gpu_info.amd,
    };

    println!("{}", serde_json::to_string_pretty(&info).unwrap());
}
