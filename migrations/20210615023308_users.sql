CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(32) NOT NULL,
  salt CHAR(64) NOT NULL,
  hashed_password VARCHAR(512) NOT NULL
);
