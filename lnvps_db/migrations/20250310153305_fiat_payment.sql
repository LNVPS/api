alter table vm_payment
    add column currency varchar(5) not null default 'BTC',
    add column payment_method      smallint unsigned not null default 0,
    add column external_id varchar(255),
    change invoice external_data varchar (4096) NOT NULL,
    drop column settle_index;
