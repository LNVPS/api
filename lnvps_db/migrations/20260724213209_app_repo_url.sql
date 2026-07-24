-- Optional canonical source repository URL for a catalog app (for README
-- rendering / a "Source" link in the app-detail page).
ALTER TABLE app ADD COLUMN repo_url VARCHAR(512) NULL DEFAULT NULL;
