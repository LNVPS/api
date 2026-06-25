-- Telegram notification channel: per-user opt-in, linked chat id, and a
-- one-time token used to associate a Telegram chat with an account.
alter table users
    add column contact_telegram bool not null default 0,
    add column telegram_chat_id bigint null,
    add column telegram_link_token varchar(64) null;

-- Token is looked up when the bot receives `/start <token>`.
create index ix_users_telegram_link_token on users (telegram_link_token);
