
CREATE TABLE user_id (
    user_id         BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    PERFORM "manage_updated_at"('user_id');
END $$;