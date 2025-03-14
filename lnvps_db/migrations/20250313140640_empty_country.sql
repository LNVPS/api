alter table users
    change column country_code country_code varchar (3);
-- assume country_code was not actually set until now
update users
set country_code = null;