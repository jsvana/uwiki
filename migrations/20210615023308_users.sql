CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(32),
  salt CHAR(64),
  hashed_password VARCHAR(512)
);
