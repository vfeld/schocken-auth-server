CREATE TABLE session (
    session_id      TEXT PRIMARY KEY,
    user_id         BIGSERIAL NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    PERFORM "manage_updated_at"('session');
END $$;