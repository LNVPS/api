-- Coarse, many-to-many grouping labels for the app catalog.
--
-- This is the second axis `App::category` wrote down as a known trade-off:
-- category values are specific enough to build a page title from ("Community
-- Nostr relay") and therefore do not group, so a "show me all relays" facet
-- needs something coarser. `category` is unchanged and still NOT NULL -- the
-- two answer different questions and neither replaces the other.
--
-- A coarser *column* was that note's guess and it is the wrong shape: route96
-- is legitimately both a media server and a Nostr thing, so the grouping axis
-- is many-to-many. A column forces a false choice; a set does not.
--
-- A real table rather than a JSON/CSV column on `app` because the reverse
-- lookup (all apps carrying tag X) is the whole point and has to be indexed --
-- otherwise /apps/tag/nostr is a full scan and the facet counts are N+1. A
-- free-string column also drifts: `Nostr relay`, `nostr-relay` and `nostr`
-- become three distinct "tags" the first time two admins type them, which is
-- the same silent degradation `category` was made NOT NULL to avoid.
--
-- Named CONSTRAINT uq_*/fk_* with separate CREATE INDEX ix_* follows
-- 20260724123500_app_deployments.sql rather than the older inline UNIQUE KEY
-- style, and `app.id` is INTEGER UNSIGNED to match it.
CREATE TABLE app_tag
(
    id           INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    -- URL-safe: this is the path segment in /apps/tag/{slug} and the value of
    -- the ?tag= filter. Lowercase letters, digits and hyphens, no spaces.
    slug         VARCHAR(64)      NOT NULL,
    -- What a human sees on a chip or a landing-page heading. Stored rather
    -- than derived from the slug because title-casing in JS mangles NIP-96,
    -- HTTP and Git -- the same argument App::category makes about <title>.
    display_name VARCHAR(100)     NOT NULL,
    -- Optional lede for a tag landing page. Nullable: a tag that only ever
    -- renders as a filter chip never needs one.
    description  VARCHAR(500)     NULL DEFAULT NULL,
    created      DATETIME         NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_app_tag_slug UNIQUE (slug)
);

CREATE TABLE app_tag_assignment
(
    id      INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    app_id  INTEGER UNSIGNED NOT NULL,
    tag_id  INTEGER UNSIGNED NOT NULL,
    created DATETIME         NOT NULL DEFAULT NOW(),
    -- CASCADE on both sides: deleting an app or retiring a tag should not
    -- leave orphan rows or force a two-step admin flow. This deliberately
    -- differs from fk_app_deployment_app, which has no cascade because a
    -- deployment is billable and an assignment is not.
    CONSTRAINT fk_app_tag_assignment_app FOREIGN KEY (app_id) REFERENCES app (id) ON DELETE CASCADE,
    CONSTRAINT fk_app_tag_assignment_tag FOREIGN KEY (tag_id) REFERENCES app_tag (id) ON DELETE CASCADE,
    CONSTRAINT uq_app_tag_assignment UNIQUE (app_id, tag_id)
);

-- uq_app_tag_assignment (app_id, tag_id) already covers the app_id lookup as a
-- leftmost prefix, so only the reverse direction needs its own index.
CREATE INDEX ix_app_tag_assignment_tag ON app_tag_assignment (tag_id);

-- Seed vocabulary. A tag earns its place when it is either true of more than
-- one app, or the name of a protocol/standard someone types into a search box.
-- `blossom` and `nip-96` are one-app tags that qualify on the second rule.
--
-- `community` and `personal` are deliberately absent: they are adjectives,
-- they would be one-app tags forever, and `category` already carries exactly
-- that distinction as "Community Nostr relay" / "Personal Nostr relay". If
-- they are wanted later they cost one INSERT each.
INSERT INTO app_tag (slug, display_name)
VALUES ('nostr', 'Nostr'),
       ('relay', 'Relay'),
       ('media-server', 'Media server'),
       ('blossom', 'Blossom'),
       ('nip-96', 'NIP-96');

-- One-shot backfill for the five catalog apps that exist today, matched by
-- slug. Inert once it has run, and a database holding none of these names
-- simply gets no assignments rather than failing.
INSERT INTO app_tag_assignment (app_id, tag_id)
SELECT a.id, t.id
FROM app a
         JOIN app_tag t
WHERE (t.slug = 'nostr' AND
       a.name IN ('strfry', 'nostr-rs-relay', 'pyramid-relay', 'haven-relay', 'route96'))
   OR (t.slug = 'relay' AND
       a.name IN ('strfry', 'nostr-rs-relay', 'pyramid-relay', 'haven-relay'))
   OR (t.slug IN ('media-server', 'blossom', 'nip-96') AND a.name = 'route96');
