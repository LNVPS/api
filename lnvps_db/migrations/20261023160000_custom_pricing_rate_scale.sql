-- Custom pricing rates are per billing interval (vm_custom_pricing.interval_*),
-- held in 1/rate_scale of the currency's minor unit (cents, millisats). A scale
-- of 1 is plain cents, so every existing model is unchanged; a finer scale lets
-- a short interval carry a fraction of a cent (an hourly share of a monthly
-- price is far below one cent). Applies to the model's rate columns and to the
-- cost of its vm_custom_pricing_disk rows.
ALTER TABLE vm_custom_pricing
    ADD COLUMN rate_scale BIGINT UNSIGNED NOT NULL DEFAULT 1 AFTER currency;
