-- Throwaway databases for the Phase 4 test suites.
--
-- Run once, by the postgres image's entrypoint, the first time the data
-- volume is created. Both databases are created empty; the suites build
-- their own schema:
--
--   complianceiq_test           tests/integration/persistence/test_persistence.py
--                               (schema from Base.metadata.create_all)
--   complianceiq_migration_test tests/integration/persistence/test_migrations.py
--                               (schema from `alembic upgrade head`, and
--                               dropped and rebuilt repeatedly, which is
--                               why it must not share a database with
--                               anything else)
--
-- Keeping test data out of `complianceiq` matters more than it looks: a
-- suite that TRUNCATEs every table would otherwise wipe whatever the
-- developer was looking at.

CREATE DATABASE complianceiq_test OWNER complianceiq;
CREATE DATABASE complianceiq_migration_test OWNER complianceiq;
