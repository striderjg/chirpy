-- +goose Up
ALTER TABLE users
ADD is_chirpy_red BOOL NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE DROP is_chirpy_red;