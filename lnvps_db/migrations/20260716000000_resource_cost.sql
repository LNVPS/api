-- Optional cost tracking (issue #82).
--
-- Rather than adding cost columns directly to `vm_host` and `ip_range`, costs
-- are stored in a single generic table weakly linked to any resource by
-- (resource_type, resource_id). This keeps the cost model extensible (new
-- resource kinds need no schema change) and lets a single resource carry
-- multiple cost records (e.g. a host has a recurring monthly rent AND a
-- one-time hardware investment).
--
-- All cost data is admin-only and optional: absence of a row means no cost
-- data for that resource (no behaviour change). Amounts are in the smallest
-- currency units (cents for fiat, millisats for BTC). For an `ip_range`
-- recurring cost, `amount` is the cost per single IP.
--
-- resource_type: 0 = vm_host, 1 = ip_range, 2 = generic (no FK; identified by
--                `label`, e.g. a colo/transit subscription)
-- cost_type:     0 = recurring, 1 = one_time (capital investment)
-- interval_type: 0 = Day, 1 = Month, 2 = Year (NULL for one_time)
CREATE TABLE resource_cost
(
    id              INTEGER UNSIGNED  NOT NULL AUTO_INCREMENT PRIMARY KEY,
    -- Weak link: what kind of resource this cost belongs to
    resource_type   TINYINT UNSIGNED  NOT NULL,
    -- Weak link: id within that resource's table (no FK, may be soft-deleted).
    -- Unused (0) for generic costs.
    resource_id     INTEGER UNSIGNED  NOT NULL,
    -- Free-form label for costs not tied to an internal entity (required for
    -- generic costs; optional otherwise)
    label           VARCHAR(200)      NULL,
    -- Recurring charge vs one-time capital cost
    cost_type       TINYINT UNSIGNED  NOT NULL,
    -- Cost amount in smallest currency units (per-IP for ip_range recurring)
    amount          BIGINT UNSIGNED   NOT NULL,
    -- Currency code, e.g. 'USD', 'EUR'
    currency        VARCHAR(10)       NOT NULL,
    -- Billing interval for recurring costs (e.g. 1 month); NULL for one-time
    interval_amount INTEGER UNSIGNED  NULL,
    interval_type   TINYINT UNSIGNED  NULL,
    -- Date the cost starts / one-time purchase was made
    billing_start   TIMESTAMP         NULL,
    -- Date the recurring cost stops being paid; NULL = still active/ongoing.
    -- Costs only count towards P/L while now() is within [billing_start, billing_end).
    billing_end     TIMESTAMP         NULL,
    created         TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated         TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_resource_cost_lookup (resource_type, resource_id, cost_type)
) DEFAULT CHARSET = utf8mb4;
