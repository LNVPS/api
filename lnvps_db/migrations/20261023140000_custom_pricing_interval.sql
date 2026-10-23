-- Billing interval of VMs built from a custom pricing model. Rates stay
-- monthly-denominated; the interval only sets how often the VM is billed and
-- how much of the monthly price each period charges. Defaults to monthly so
-- existing models are unchanged. 0=Day, 1=Month, 2=Year, 3=Hour.
ALTER TABLE vm_custom_pricing
    ADD COLUMN interval_amount INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN interval_type   SMALLINT UNSIGNED NOT NULL DEFAULT 1;
