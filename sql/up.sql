CREATE TABLE IF NOT EXISTS users ( 
    id INTEGER PRIMARY KEY,

    created_on_utc DATETIME NOT NULL,
    email VARCHAR(255) NOT NULL,
    email_verified TINYINT(1) NOT NULL DEFAULT(0),
    password_hash VARCHAR(255) NOT NULL,
    last_login DATETIME
);

CREATE TABLE IF NOT EXISTS email_verifications (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_str CHAR(64) NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX email_verifications_token_index ON email_verifications(token_str);

CREATE TABLE IF NOT EXISTS refresh_tokens(
    id INTEGER PRIMARY KEY,

    user_id INTEGER NOT NULL,
    created_on TIMESTAMP NOT NULL DEFAULT(CURRENT_TIMESTAMP),
    expires_on TIMESTAMP NOT NULL,
    revoked_on TIMESTAMP,
    revoked_by CHAR(48),
    token_str CHAR(64) NOT NULL,
    next_token_id INTEGER,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (next_token_id) REFERENCES refresh_tokens(id)
);

CREATE INDEX token_str_index ON refresh_tokens (token_str);