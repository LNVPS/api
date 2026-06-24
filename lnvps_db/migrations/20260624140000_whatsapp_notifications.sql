-- WhatsApp notification channel: per-user opt-in, the (E.164) number, a
-- verification flag and a pending one-time verification code.
alter table users
    add column contact_whatsapp bool not null default 0,
    add column whatsapp_number varchar(32) null,
    add column whatsapp_verified bool not null default 0,
    add column whatsapp_verify_code varchar(12) null;
