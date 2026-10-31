CREATE TABLE users (
    id         BIGSERIAL PRIMARY KEY,
    login      TEXT UNIQUE NOT NULL,
    auth_hash  TEXT NOT NULL,
    revision   BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE items (
    id         UUID NOT NULL,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    version    BIGINT NOT NULL,
    revision   BIGINT NOT NULL,
    deleted    BOOLEAN NOT NULL DEFAULT false,
    payload    BYTEA,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);

CREATE INDEX items_user_revision_idx ON items (user_id, revision);
