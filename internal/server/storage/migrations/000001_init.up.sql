CREATE TABLE users (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login      VARCHAR(64) UNIQUE NOT NULL,
    auth_hash  VARCHAR(60) NOT NULL,
    revision   BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE items (
    id         UUID NOT NULL,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    version    BIGINT NOT NULL,
    revision   BIGINT NOT NULL,
    deleted    BOOLEAN NOT NULL DEFAULT false,
    name       VARCHAR(256) NOT NULL DEFAULT '',
    meta       TEXT NOT NULL DEFAULT '',
    payload    BYTEA,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);

CREATE INDEX items_user_revision_idx ON items (user_id, revision);
