-- Add migration script here
create table nostr_domain
(
    id       integer unsigned not null auto_increment primary key,
    owner_id integer unsigned not null,
    name     varchar(200) not null,
    enabled  bit(1)       not null default 0,
    created  timestamp    not null default current_timestamp,
    relays   varchar(1024),

    unique key ix_domain_unique (name),
    constraint fk_nostr_domain_user foreign key (owner_id) references users (id)
);
create table nostr_domain_handle
(
    id        integer unsigned not null auto_increment primary key,
    domain_id integer unsigned not null,
    handle    varchar(100) not null,
    created   timestamp    not null default current_timestamp,
    pubkey    binary(32) not null,
    relays    varchar(1024),

    unique key ix_domain_handle_unique (domain_id, handle),
    constraint fk_nostr_domain_handle_domain foreign key (domain_id) references nostr_domain (id) on delete cascade
)