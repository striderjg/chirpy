-- name: SetRefreshToken :one
INSERT INTO refresh_tokens(created_at, updated_at, expires_at, token, user_id)
VALUES(
    NOW(),
    NOW(),
    NOW() + INTERVAL '60 DAY',
    $1,
    $2
)
RETURNING *;

-- name: GetUserFromRefreshToken :one
SELECT users.* FROM refresh_tokens
INNER JOIN users ON refresh_tokens.user_id = users.id
WHERE refresh_tokens.token = $1 AND refresh_tokens.revoked_at IS NULL;

-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at=NOW(), updated_at=NOW()
WHERE token=$1;
