-- Catalog metadata used to build the public app page's search-facing copy.
--
-- `category` is the class of software the app is ("Nostr relay", "Blossom
-- media server", "Git server"). Deliberately free text rather than an enum:
-- an enum would need a migration per newly-onboarded class of app, and the
-- catalog is not limited to one ecosystem. It is what lets the frontend
-- template a title from data instead of hardcoding one per slug.
--
-- It is NOT NULL because a nullable category renders a correct-but-generic
-- title and errors nowhere -- the same silent failure the hardcoded per-slug
-- frontend map produced, moved one layer down. Add -> backfill -> NOT NULL in
-- one file follows 20260217000000_require_company_id.sql.
--
-- `seo_title` / `seo_description` are per-app overrides for when the template
-- is not good enough. They arrive over the wire, so they are never picked up
-- by formatjs extraction in LNVPS/web and can only ever be English; the
-- template built from `category` is the path that localises.
ALTER TABLE app
    ADD COLUMN category        VARCHAR(100) NULL DEFAULT NULL,
    ADD COLUMN seo_title       VARCHAR(255) NULL DEFAULT NULL,
    ADD COLUMN seo_description VARCHAR(500) NULL DEFAULT NULL;

-- Reviewed copy for the five catalog apps that exist today. Sentence case with
-- proper nouns capitalised, no article, no "hosting"/"managed", no trailing
-- punctuation -- the frontend template supplies all of those. Values are more
-- specific than a taxonomy bucket on purpose: bucketing gives four of these
-- five an identical title suffix and throws away the distinction the
-- hand-written copy carried.
--
-- Matching by slug is a one-shot backfill against rows that already exist,
-- inert once it has run. That is not the coupling this migration removes: the
-- frontend map it replaces was consulted on every render, forever, and
-- degraded silently for every app it did not know about.
UPDATE app SET category = 'Nostr relay'           WHERE name = 'strfry';
UPDATE app SET category = 'Blossom media server'  WHERE name = 'route96';
UPDATE app SET category = 'Nostr relay'           WHERE name = 'nostr-rs-relay';
UPDATE app SET category = 'Community Nostr relay' WHERE name = 'pyramid-relay';
UPDATE app SET category = 'Personal Nostr relay'  WHERE name = 'haven-relay';

-- Safety net so the NOT NULL below cannot fail (strict mode) or silently
-- coerce to '' (non-strict) on a database holding an app outside the five
-- above. A row landing here is a placeholder, not reviewed copy: it renders
-- "<App> Hosting -- Managed self-hosted application" until an admin sets a
-- real value.
UPDATE app SET category = 'Self-hosted application' WHERE category IS NULL;

ALTER TABLE app MODIFY COLUMN category VARCHAR(100) NOT NULL;
