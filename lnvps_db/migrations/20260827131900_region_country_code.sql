-- Regions carried their country as a suffix in the display name, e.g.
-- "Amsterdam (NL)". Store it as a proper column so clients can render a flag or
-- filter by country without parsing the name. Existing rows are left NULL and
-- are set through the admin API.
ALTER TABLE region
    ADD COLUMN country_code char(2) NULL COMMENT 'ISO 3166-1 alpha-2 country code';
