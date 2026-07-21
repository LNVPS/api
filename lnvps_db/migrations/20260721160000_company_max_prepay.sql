-- Cap how far in advance a subscription can be prepaid/renewed. Bounds both a
-- single large `intervals` request and repeated back-to-back renewals: a renewal
-- is rejected once it would push the subscription expiry beyond
-- `now + max_prepay_days`. `0` means "inherit the global default" (settings).
alter table company
    add column max_prepay_days smallint unsigned not null default 0;
