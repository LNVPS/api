alter table vm_payment
    add column payment_type smallint unsigned not null default 0;