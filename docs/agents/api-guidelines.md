# API Guidelines

## Project-Specific Rules

- **Always return amounts in API responses as cents / milli-sats**
- **Never add JavaScript code examples to API documentation**
- **Never expose secrets in admin API responses** — tokens, API keys, webhook secrets, and other sensitive values must never be returned in GET/list responses. Use sanitized structs with boolean indicators (e.g., `has_token: true`) instead of actual values.
- **All `list_*` APIs must use database-level pagination** — never fetch all rows and paginate in Rust (skip/take). Use `LIMIT ? OFFSET ?` in the SQL query, and return a separate `COUNT(*)` or equivalent for the `total` field in the paginated response. Results must be ordered deterministically (typically `ORDER BY id DESC` or `ORDER BY created DESC`) so pagination is stable across requests.

## Documentation Requirements

When modifying any API (user-facing or admin), you **MUST**:

1. **Update the API documentation** — Keep `ADMIN_API_ENDPOINTS.md` and any other API docs in sync with code changes.
2. **Update the API changelog** — Add an entry to `API_CHANGELOG.md` with:
   - Date of change
   - Type of change (Added, Changed, Deprecated, Removed, Fixed, Security)
   - Brief description of what changed
   - Which endpoints are affected
