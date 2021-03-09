.headers on
.mode line

CREATE TABLE IF NOT EXISTS users (
	id TEXT NOT NULL PRIMARY KEY,
	email TEXT NOT NULL UNIQUE,
	is_verified INT NOT NULL DEFAULT 0,
	login_token TEXT NOT NULL,
	telegram_user_chat_id INT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS mailboxes (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    mailbox_for TEXT,
    is_blocked INT NOT NULL DEFAULT 0,
    generated_email TEXT NOT NULL,
    relay_to_mail INT NOT NULL DEFAULT 1,
    relay_to_telegram INT NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS mails (
    id TEXT NOT NULL PRIMARY KEY,
    mailbox_id TEXT NOT NULL,
    s3_file_id TEXT UNIQUE,
    received_at TEXT,
    relayed_at TEXT ,
    telegram_relay_fail_reason TEXT,
    is_relayed INT NOT NULL DEFAULT 0,
    spam_verdict TEXT,
    virus_verdict TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    email_from TEXT NOT NULL,
    relayed_to_email INT NOT NULL DEFAULT 0,
    relayed_to_telegram INT NOT NULL DEFAULT 0,
    FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id)
);