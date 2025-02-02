-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: UpdateUserByID :one
UPDATE users SET updated_at=NOW(), email=$2, hashed_password=$3
WHERE id = $1
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: SetChirpyRedByID :exec
UPDATE users SET is_chirpy_red=true
WHERE id=$1;

-- name: DeleteUsers :exec
DELETE FROM users;