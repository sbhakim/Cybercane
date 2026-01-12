FROM postgis/postgis:17-3.5

# pgvector for PostgreSQL 17
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-17-pgvector \
 && rm -rf /var/lib/apt/lists/*
