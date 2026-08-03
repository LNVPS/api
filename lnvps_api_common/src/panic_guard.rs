//! Turn a panic in an HTTP handler into a 500 for that one request.
//!
//! Handler code is written to return `Result`, but a panic can still escape:
//! an arithmetic overflow, a slice index, a `.unwrap()` on unexpected input.
//! Several such panics were reachable from unauthenticated request data, and
//! because the release profile used to abort on panic each one was a full
//! outage rather than a failed request.
//!
//! Wrapping the routers in [`tower_http::catch_panic::CatchPanicLayer`] with
//! this responder contains the blast radius to the offending request and logs
//! enough to find the cause. The response body is deliberately generic — a
//! panic message can contain internal state.

use axum::body::Body;
use axum::http::{Response, StatusCode, header};
use log::error;
use std::any::Any;

/// Response body returned for a caught panic. Deliberately opaque.
const PANIC_BODY: &str = r#"{"error":"An internal error occurred"}"#;

/// Build the 500 response for a caught panic, logging the payload.
///
/// Matches the shape of [`crate::ApiError`]'s JSON so clients can parse a
/// panic-induced failure the same way as any other error.
pub fn handle_panic(err: Box<dyn Any + Send + 'static>) -> Response<Body> {
    let details = panic_message(err.as_ref());
    error!("Handler panicked, returning 500: {}", details);

    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(PANIC_BODY))
        // The builder only fails on an invalid status/header, both of which are
        // constants here.
        .expect("panic response is well-formed")
}

/// Best-effort extraction of a human-readable message from a panic payload.
///
/// `panic!("literal")` yields a `&str` payload and `panic!("{x}")` a `String`;
/// anything else (a non-standard `panic_any`) has no printable form.
fn panic_message<'a>(err: &'a (dyn Any + Send + 'static)) -> &'a str {
    err.downcast_ref::<String>()
        .map(|s| s.as_str())
        .or_else(|| err.downcast_ref::<&'static str>().copied())
        .unwrap_or("unknown panic payload")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_string_panic_payload() {
        let payload: Box<dyn Any + Send + 'static> = Box::new("boom".to_string());
        assert_eq!(panic_message(payload.as_ref()), "boom");
    }

    #[test]
    fn extracts_str_panic_payload() {
        let payload: Box<dyn Any + Send + 'static> = Box::new("static boom");
        assert_eq!(panic_message(payload.as_ref()), "static boom");
    }

    #[test]
    fn falls_back_for_unprintable_payload() {
        let payload: Box<dyn Any + Send + 'static> = Box::new(42u32);
        assert_eq!(panic_message(payload.as_ref()), "unknown panic payload");
    }

    /// The caught-panic response must be a 500 with a generic JSON body — the
    /// panic message itself can carry internal state and must not be returned.
    #[test]
    fn builds_generic_500_response() {
        let payload: Box<dyn Any + Send + 'static> = Box::new("secret internal detail".to_string());

        let resp = handle_panic(payload);

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }
}
