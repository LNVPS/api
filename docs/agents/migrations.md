# Database Migrations

## Timestamp Rules

**CRITICAL:** Migration filenames must have unique timestamps (full 14-digit `YYYYMMDDHHMMSS`). Before creating or modifying a migration:

1. **Check existing timestamps** — Run `ls lnvps_db/migrations/` and verify your full timestamp doesn't conflict
2. **After rebasing** — If your branch adds migrations, check that the timestamps don't collide with migrations added to master
3. **Use the current timestamp** — Generate with `date +%Y%m%d%H%M%S`

Migration format: `YYYYMMDDHHMMSS_description.sql`

Example conflict to avoid:
```
20260219000000_cpu_type.sql            # from master
20260219000000_email_verification.sql  # CONFLICT — same full timestamp!
```

Fix by using a completely unique timestamp:
```
20260219000000_cpu_type.sql
20260221120000_email_verification.sql  # different date AND time
```

## Migration Best Practices

- Use `NOT NULL DEFAULT <value>` for new columns to avoid breaking existing rows
- Test migrations against a database with production-like data
- Never modify a migration that has already been applied to any environment
