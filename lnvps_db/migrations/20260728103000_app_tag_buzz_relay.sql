-- buzz-relay was added to the catalog after 20260727090000_app_tags.sql, whose
-- backfill named the five apps that existed when it was written, so the row
-- carries no tags at all and is invisible to every tag filter -- including
-- ?tag=nostr, not only ?tag=relay.
--
-- `nostr` + `relay` matches pyramid-relay, which shares its category
-- ("Community Nostr relay"). Being a workspace as well as a relay is not a
-- reason to withhold `relay`: the tag axis is many-to-many precisely so an app
-- that is two things is filed under both.
--
-- Matched by name and inert against a database that does not hold the row,
-- following the backfill in 20260727090000_app_tags.sql. IGNORE so a catalog
-- that was already corrected by hand is not a failed migration.
INSERT IGNORE INTO app_tag_assignment (app_id, tag_id)
SELECT a.id, t.id
FROM app a
         JOIN app_tag t
WHERE a.name = 'buzz-relay'
  AND t.slug IN ('nostr', 'relay');
