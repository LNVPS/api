-- Store IP-derived geolocation as a second, independent piece of place-of-supply
-- evidence for EU VAT on electronically supplied services. Kept separate from the
-- self-declared `country_code` so the two signals can be compared and conflicts
-- flagged when determining whether/what VAT to charge.
alter table users
    add column geo_country_code varchar(3) null,
    add column geo_ip varchar(45) null,
    add column geo_updated timestamp null;
