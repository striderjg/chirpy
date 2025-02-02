-- +goose Up
ALTER TABLE users 
ADD hashed_password TEXT NOT NULL
CONSTRAINT df_hashed_password DEFAULT 'unset';

-- +goose Down
ALTER TABLE users
DROP hashed_password;