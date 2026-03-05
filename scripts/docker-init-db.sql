-- Crypto Claw PostgreSQL initialization script
-- Executed automatically by the postgres Docker container on first run.

CREATE DATABASE cclaw_a;
CREATE DATABASE cclaw_b;

CREATE USER cclaw WITH PASSWORD 'cclaw';

GRANT ALL PRIVILEGES ON DATABASE cclaw_a TO cclaw;
GRANT ALL PRIVILEGES ON DATABASE cclaw_b TO cclaw;

-- Grant schema permissions (required for PostgreSQL 15+)
\connect cclaw_a
GRANT ALL ON SCHEMA public TO cclaw;

\connect cclaw_b
GRANT ALL ON SCHEMA public TO cclaw;
