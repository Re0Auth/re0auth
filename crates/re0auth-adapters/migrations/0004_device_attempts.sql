CREATE TABLE device_attempts (
    ip TEXT NOT NULL,
    user_code_hash BLOB NOT NULL,
    misses INTEGER NOT NULL,
    last_miss_at INTEGER NOT NULL,
    PRIMARY KEY (ip, user_code_hash)
);

CREATE INDEX idx_device_attempts_last_miss ON device_attempts (last_miss_at);
