//! GPU detection for NVIDIA (NVML) and AMD (sysfs)

use crate::{DetectionResult, GpuMfg};
use std::path::Path;

/// Combined GPU detection result
pub struct GpuInfo {
    pub mfg: GpuMfg,
    pub model: Option<String>,
    pub features: Vec<String>,
    /// NVIDIA NVML detection result
    pub nvml: DetectionResult,
    /// AMD GPU detection result
    pub amd: DetectionResult,
}

/// Detect NVIDIA GPUs with NVENC/NVDEC support using NVML
pub fn detect_nvidia() -> DetectionResult {
    use nvml_wrapper::enum_wrappers::device::EncoderType;
    use nvml_wrapper::Nvml;

    let mut features = Vec::new();

    // Initialize NVML
    let nvml = match Nvml::init() {
        Ok(n) => n,
        Err(e) => return DetectionResult::error(format!("NVML init failed: {e}")),
    };

    // Get device count
    let device_count = match nvml.device_count() {
        Ok(c) => c,
        Err(e) => return DetectionResult::error(format!("failed to get device count: {e}")),
    };

    if device_count == 0 {
        return DetectionResult::NotFound;
    }

    // Check capabilities of the first GPU (primary)
    let device = match nvml.device_by_index(0) {
        Ok(d) => d,
        Err(e) => {
            // Have NVIDIA GPU but can't query details
            return DetectionResult::error(format!("failed to query device 0: {e}"));
        }
    };

    // Get GPU name
    let model = device.name().ok();

    // Get GPU architecture via compute capability
    let (major, minor) = match device.cuda_compute_capability() {
        Ok(cc) => (cc.major, cc.minor),
        Err(_) => (0, 0),
    };

    // Check encoder capabilities directly from NVML
    if let Ok(encoder_cap) = device.encoder_capacity(EncoderType::H264) {
        if encoder_cap > 0 {
            features.push("EncodeH264".to_string());
        }
    }
    if let Ok(encoder_cap) = device.encoder_capacity(EncoderType::HEVC) {
        if encoder_cap > 0 {
            features.push("EncodeHEVC".to_string());
        }
    }

    // Fallback to compute capability if encoder_capacity doesn't work
    if !features.contains(&"EncodeH264".to_string()) && major >= 3 {
        // Kepler (SM 3.0+) and newer support NVENC H.264
        features.push("EncodeH264".to_string());
    }
    if !features.contains(&"EncodeHEVC".to_string()) && (major > 5 || (major == 5 && minor >= 2)) {
        // Maxwell Gen 2 (SM 5.2+) and newer support HEVC
        features.push("EncodeHEVC".to_string());
    }

    // Decoder capabilities based on compute capability
    // Kepler+ supports H.264 decode
    if major >= 3 {
        features.push("DecodeH264".to_string());
    }

    // Maxwell Gen 2+ supports HEVC decode
    if major > 5 || (major == 5 && minor >= 2) {
        features.push("DecodeHEVC".to_string());
    }

    // Pascal (SM 6.x) and newer support VP9 decode
    if major >= 6 {
        features.push("DecodeVP9".to_string());
    }

    // Ampere (SM 8.6+) supports AV1 decode
    // GA10x chips are SM 8.6
    if major > 8 || (major == 8 && minor >= 6) {
        features.push("DecodeAV1".to_string());
    }

    // Ada Lovelace (SM 8.9) supports AV1 encode
    // AD10x chips are SM 8.9
    if major > 8 || (major == 8 && minor >= 9) {
        features.push("EncodeAV1".to_string());
    }

    match model {
        Some(name) => DetectionResult::ok_with_name(name, features),
        None => DetectionResult::ok(features),
    }
}

/// Detect AMD discrete GPUs with VCN/AMF support
#[cfg(target_os = "linux")]
pub fn detect_amd() -> DetectionResult {
    let mut features = Vec::new();
    let mut model: Option<String> = None;

    // Check for AMD GPU via sysfs
    // Look for amdgpu driver in /sys/bus/pci/drivers/amdgpu/
    let amdgpu_driver_path = Path::new("/sys/bus/pci/drivers/amdgpu");
    if !amdgpu_driver_path.exists() {
        return DetectionResult::NotFound;
    }

    // Check if there are any bound devices
    let entries = match std::fs::read_dir(amdgpu_driver_path) {
        Ok(e) => e,
        Err(e) => return DetectionResult::error(format!("failed to read amdgpu driver: {e}")),
    };

    let has_gpu = entries
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with("0000:"));

    if !has_gpu {
        return DetectionResult::NotFound;
    }

    // AMD GPUs with VCN (Video Core Next) support hardware encode/decode
    // VCN is present in Vega and newer (RDNA, RDNA2, RDNA3)
    // Most modern AMD GPUs support these via VCN/AMF
    features.push("EncodeH264".to_string());
    features.push("EncodeHEVC".to_string());
    features.push("DecodeH264".to_string());
    features.push("DecodeHEVC".to_string());
    features.push("DecodeVP9".to_string());

    // Check for VCN version to determine AV1 support
    // VCN 3.0+ (RDNA2) supports AV1 decode, VCN 4.0+ (RDNA3) supports AV1 encode

    // Try to detect GPU generation from device files
    if let Ok(drm_entries) = std::fs::read_dir("/sys/class/drm") {
        for entry in drm_entries.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("card") || name_str.contains('-') {
                continue;
            }

            // Read the device marketing name or check for VCN version
            let product_name_path = entry.path().join("device/product_name");
            if let Ok(product) = std::fs::read_to_string(&product_name_path) {
                let product_trimmed = product.trim().to_string();
                let product_lower = product_trimmed.to_lowercase();

                // Save the model name if we haven't found one yet
                if model.is_none() && !product_trimmed.is_empty() {
                    model = Some(product_trimmed);
                }

                // RDNA3 (RX 7000 series) supports AV1 encode
                if product_lower.contains("7900")
                    || product_lower.contains("7800")
                    || product_lower.contains("7700")
                    || product_lower.contains("7600")
                {
                    features.push("EncodeAV1".to_string());
                    features.push("DecodeAV1".to_string());
                }
                // RDNA2 (RX 6000 series) supports AV1 decode only
                else if product_lower.contains("6900")
                    || product_lower.contains("6800")
                    || product_lower.contains("6700")
                    || product_lower.contains("6600")
                    || product_lower.contains("6500")
                    || product_lower.contains("6400")
                {
                    features.push("DecodeAV1".to_string());
                }
            }
        }
    }

    match model {
        Some(name) => DetectionResult::ok_with_name(name, features),
        None => DetectionResult::ok(features),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn detect_amd() -> DetectionResult {
    DetectionResult::Unsupported
}

/// Detect all discrete GPUs and return combined info
pub fn detect_gpu() -> GpuInfo {
    let nvml = detect_nvidia();
    let amd = detect_amd();

    // Determine primary GPU (prefer NVIDIA if both present)
    let (mfg, model, features) = if nvml.is_ok() {
        (
            GpuMfg::Nvidia,
            nvml.name().map(String::from),
            nvml.features().to_vec(),
        )
    } else if amd.is_ok() {
        (
            GpuMfg::Amd,
            amd.name().map(String::from),
            amd.features().to_vec(),
        )
    } else {
        (GpuMfg::None, None, Vec::new())
    };

    GpuInfo {
        mfg,
        model,
        features,
        nvml,
        amd,
    }
}
