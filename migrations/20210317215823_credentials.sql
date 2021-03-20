
CREATE TABLE credentials (
    user_id         BIGSERIAL PRIMARY KEY,
    login_name      TEXT NOT NULL UNIQUE,
    pwd             TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    PERFORM "manage_updated_at"('credentials');
END $$;