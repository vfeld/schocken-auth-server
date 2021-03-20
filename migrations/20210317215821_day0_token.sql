
CREATE TABLE day0_token (
    token           TEXT PRIMARY KEY,
    valid           BOOLEAN NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    PERFORM "manage_updated_at"('day0_token');
END $$;