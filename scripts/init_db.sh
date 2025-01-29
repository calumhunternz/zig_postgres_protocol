#!/usr/bin/env bash
set -x
set -eo pipefail

# Check if psql is installed
if ! [ -x "$(command -v psql)" ]; then
    echo >&2 "Error: psql is not installed."
    exit 1
fi

# Check if a custom user has been set, otherwise default to 'postgres'
DB_USER="${POSTGRES_USER:=postgres}"
# Check if a custom password has been set, otherwise default to 'password'
DB_PASSWORD="${POSTGRES_PASSWORD:=password}"
# Check if a custom database name has been set, otherwise default to 'zig_db'
DB_NAME="${POSTGRES_DB:=zig_db}"
# Check if a custom port has been set, otherwise default to '5433'
DB_PORT="${POSTGRES_PORT:=5433}"
# Check if a custom host has been set, otherwise default to 'localhost'
DB_HOST="${POSTGRES_HOST:=localhost}"

# Start Docker container if SKIP_DOCKER is not set
if [[ -z "${SKIP_DOCKER}" ]]
then
    docker run \
        --name cv_server_db \
        -v ~/pg-docker/conf/postgresql.conf:/etc/postgresql/postgresql.conf \
        -v ~/pg-docker/logs:/var/log/postgresql \
        -e POSTGRES_USER=${DB_USER} \
        -e POSTGRES_PASSWORD=${DB_PASSWORD} \
        -e POSTGRES_DB=${DB_NAME} \
        -p "${DB_PORT}":5432 \
        -d postgres \
        postgres -N 1000 \
        -c 'config_file=/etc/postgresql/postgresql.conf' \
        # ^ Increased maximum number of connections for testing purposes
fi

# Keep pinging Postgres until it's ready to accept commands
export PGPASSWORD="${DB_PASSWORD}"

until psql -h "${DB_HOST}" -U "${DB_USER}" -p "${DB_PORT}" -d "postgres" -c '\q'; do
    >&2 echo "Postgres is still unavailable - sleeping"
    sleep 1
done
>&2 echo "Postgres is up and running on port ${DB_PORT}!"

# Create the database if it doesn't exist
psql -h "${DB_HOST}" -U "${DB_USER}" -p "${DB_PORT}" -d "postgres" -c "CREATE DATABASE ${DB_NAME};"

# Set the DATABASE_URL environment variable
DATABASE_URL=postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
export DATABASE_URL

# Create a random test table in the database
>&2 echo "Creating a test table in the database..."

psql -h "${DB_HOST}" -U "${DB_USER}" -p "${DB_PORT}" -d "${DB_NAME}" <<-EOSQL
    CREATE TABLE IF NOT EXISTS test_table (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    INSERT INTO test_table (name) VALUES ('Test Entry 1'), ('Test Entry 2');
EOSQL

>&2 echo "Test table created and populated successfully!"

