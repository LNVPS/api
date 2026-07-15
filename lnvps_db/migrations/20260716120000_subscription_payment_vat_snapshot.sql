-- Record the tax fields on each payment at the time it is created. The `tax`
-- amount (cents) already exists; these store the rate and inputs used so the
-- values can be reproduced later independently of the account or rate table.
--
-- `tax_breakdown` holds the per-line values as a JSON array. `tax_rate`,
-- `tax_country_code` and `tax_treatment` are a convenience summary, set only
-- when every line matches and left NULL when the lines differ (see
-- `tax_breakdown`). `tax_evidence` holds the country signals for the customer.
alter table subscription_payment
    add column tax_rate double null,
    add column tax_country_code varchar(3) null,
    add column tax_treatment varchar(32) null,
    add column tax_evidence json null,
    add column tax_breakdown json null;
