-- Passwordless WebAuthn / passkey login (account_type = 2).
-- One account may register several credentials (one per device). `passkey`
-- holds the JSON-serialised webauthn-rs Passkey (public key + signature
-- counter) and is the source of truth, re-serialised after each login.
create table user_webauthn_credentials
(
    id        integer unsigned not null auto_increment primary key,
    user_id   integer unsigned not null,
    cred_id   varbinary(1024)  not null,
    passkey   text             not null,
    name      varchar(100),
    created   timestamp        default current_timestamp,
    last_used timestamp        null,

    constraint fk_webauthn_cred_user foreign key (user_id) references users (id)
);
create unique index ix_webauthn_cred_id on user_webauthn_credentials (cred_id);
create index ix_webauthn_cred_user on user_webauthn_credentials (user_id);
