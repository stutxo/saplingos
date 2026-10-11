# Database schema

For the wallet's complete SQLite DDL, read `sdk/schema.sql`. Do not reconstruct
the schema by aggregating incremental migrations.

After changing migrations, run the existing schema dumper:

```sh
cargo run --locked -p sapling-sdk --example dump-sqlite-schema
```

Review stdout before updating the tracked schema. Preserve program descriptors,
recovery records, and cross-process restart semantics.

Server PostgreSQL schema and migrations belong to the pinned upstream Bark
fixtures, not this client SDK repository.
