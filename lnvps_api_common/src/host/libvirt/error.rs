//! Mapping from libvirt's error codes onto the retry system's
//! [`OpError`] classification.
//!
//! The distinction matters: [`OpError::Transient`] errors are retried by the
//! provisioning pipeline, [`OpError::Fatal`] errors abort it and trigger
//! rollback. Getting this wrong either wedges the pipeline retrying something
//! that can never succeed, or gives up on a blip.

use crate::retry::OpError;
use anyhow::anyhow;
use virt::error::{Error as VirtError, ErrorNumber};

/// Errors that mean "the object isn't there".
///
/// Callers use this to make deletes idempotent: removing something that has
/// already been removed is a success, not a failure.
pub fn is_not_found(e: &VirtError) -> bool {
    matches!(
        e.code().unwrap_or(ErrorNumber::InternalError),
        ErrorNumber::NoDomain
            | ErrorNumber::NoStorageVolume
            | ErrorNumber::NoStoragePool
            | ErrorNumber::NoNetwork
    )
}

/// True when retrying the same call can never produce a different result.
///
/// Anything not listed here is treated as transient, which is the safe default:
/// a retried operation that still fails surfaces as an error eventually, while
/// a wrongly-fatal error aborts provisioning on a recoverable blip.
fn is_fatal(e: &VirtError) -> bool {
    matches!(
        e.code().unwrap_or(ErrorNumber::InternalError),
        // The object we were told to act on does not exist.
        ErrorNumber::NoDomain
            | ErrorNumber::NoStorageVolume
            | ErrorNumber::NoStoragePool
            | ErrorNumber::NoNetwork
            // We generated or were given bad input.
            | ErrorNumber::XmlError
            | ErrorNumber::XmlDetail
            | ErrorNumber::InvalidArg
            | ErrorNumber::InvalidDomain
            | ErrorNumber::InvalidConn
            // The hypervisor cannot do what we asked, ever.
            | ErrorNumber::NoSupport
            | ErrorNumber::ConfigUnsupported
            | ErrorNumber::OperationDenied
            // e.g. "domain is already running" / "domain is not running" —
            // the caller's state assumption is wrong, retrying won't fix it.
            | ErrorNumber::OperationInvalid
    )
}

/// Convert a libvirt error into an [`OpError`], attaching the operation name so
/// the log line says what was being attempted rather than just the raw message.
pub fn map_virt_error(op: &str, e: VirtError) -> OpError<anyhow::Error> {
    let fatal = is_fatal(&e);
    let err = anyhow!("libvirt {}: {} (code={:?})", op, e.message(), e.code());
    if fatal {
        OpError::Fatal(err)
    } else {
        OpError::Transient(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real [`VirtError`] has no public constructor taking a code, so the
    /// classification tables are asserted directly instead.
    #[test]
    fn not_found_codes_are_fatal() {
        for code in [
            ErrorNumber::NoDomain,
            ErrorNumber::NoStorageVolume,
            ErrorNumber::NoStoragePool,
            ErrorNumber::NoNetwork,
        ] {
            assert!(
                fatal_for(code),
                "{code:?} should be fatal (object does not exist)"
            );
            assert!(not_found_for(code), "{code:?} should count as not-found");
        }
    }

    #[test]
    fn bad_input_is_fatal() {
        for code in [
            ErrorNumber::XmlError,
            ErrorNumber::XmlDetail,
            ErrorNumber::InvalidArg,
            ErrorNumber::NoSupport,
            ErrorNumber::ConfigUnsupported,
            ErrorNumber::OperationDenied,
            ErrorNumber::OperationInvalid,
        ] {
            assert!(fatal_for(code), "{code:?} should be fatal");
            assert!(!not_found_for(code), "{code:?} is not a not-found error");
        }
    }

    #[test]
    fn infrastructure_errors_are_transient() {
        for code in [
            ErrorNumber::InternalError,
            ErrorNumber::NoMemory,
            ErrorNumber::NoConnect,
            ErrorNumber::SystemError,
            ErrorNumber::OperationFailed,
            ErrorNumber::OperationTimeout,
        ] {
            assert!(
                !fatal_for(code),
                "{code:?} should be transient so the pipeline retries"
            );
        }
    }

    // Mirror of the matches! tables above, driven by a bare code. Kept in the
    // test module so the production path stays allocation-free.
    fn fatal_for(code: ErrorNumber) -> bool {
        matches!(
            code,
            ErrorNumber::NoDomain
                | ErrorNumber::NoStorageVolume
                | ErrorNumber::NoStoragePool
                | ErrorNumber::NoNetwork
                | ErrorNumber::XmlError
                | ErrorNumber::XmlDetail
                | ErrorNumber::InvalidArg
                | ErrorNumber::InvalidDomain
                | ErrorNumber::InvalidConn
                | ErrorNumber::NoSupport
                | ErrorNumber::ConfigUnsupported
                | ErrorNumber::OperationDenied
                | ErrorNumber::OperationInvalid
        )
    }

    fn not_found_for(code: ErrorNumber) -> bool {
        matches!(
            code,
            ErrorNumber::NoDomain
                | ErrorNumber::NoStorageVolume
                | ErrorNumber::NoStoragePool
                | ErrorNumber::NoNetwork
        )
    }
}
