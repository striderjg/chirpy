-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $2,
    $1
)
RETURNING *;

-- name: GetChirps :many
SELECT * from chirps ORDER BY created_at;

-- name: GetChripById :one
select * from chirps WHERE id = $1;

-- name: DeleteChirpById :exec
DELETE FROM chirps WHERE id=$1;