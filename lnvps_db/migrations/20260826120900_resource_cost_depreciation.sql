-- Straight-line depreciation for one-time (capital) resource costs.
--
-- Standard accrual accounting does not expense a capital purchase in the period
-- it was paid for; the asset is capitalised and expensed over its useful life.
-- `depreciation_months` is that useful life in months, applied straight-line
-- from `billing_start`.
--
-- NULL (the default, and the behaviour of every pre-existing row) = expensed in
-- full in the purchase period, preserving the previous P/L output.
ALTER TABLE resource_cost
    ADD COLUMN depreciation_months INTEGER UNSIGNED NULL;
