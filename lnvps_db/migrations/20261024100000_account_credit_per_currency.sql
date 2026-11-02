ALTER TABLE account_credit DROP PRIMARY KEY, ADD PRIMARY KEY (user_id, currency);
