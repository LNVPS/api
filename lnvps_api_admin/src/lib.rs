pub mod admin;
pub mod settings;

/// The admin API returns the underlying error text on a 500, and its tests
/// assert on it.
///
/// The binary opts in from `main`, which a unit test never runs, so without
/// this the tests would read the sanitised message every other binary gets.
/// Idempotent and safe to call from anywhere, so a test that asserts on an
/// error body can call it without caring whether another test already has:
/// the switch is process-wide, and a test that only worked when it happened to
/// run first would be exactly the order-dependent flake worth avoiding.
#[cfg(test)]
pub(crate) fn verbose_errors_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| lnvps_api_common::set_verbose_internal_errors(true));
}
