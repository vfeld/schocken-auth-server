
CREATE TABLE role_binding (
    binding_id      BIGSERIAL PRIMARY KEY,
    user_id         BIGSERIAL NOT NULL,
    role_name       TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    PERFORM "manage_updated_at"('role_binding');
END $$;