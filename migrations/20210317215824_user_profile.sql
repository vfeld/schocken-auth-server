
CREATE TABLE user_profile (
    user_id         BIGSERIAL PRIMARY KEY,
    email           TEXT NOT NULL,
    first_name      TEXT,
    last_name       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    PERFORM "manage_updated_at"('user_profile');
END $$;