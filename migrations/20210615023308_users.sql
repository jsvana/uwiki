CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(32) NOT NULL UNIQUE,
  password VARCHAR(512) NOT NULL,
  admin BOOLEAN NOT NULL DEFAULT FALSE,
  state VARCHAR(8) NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'rejected')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
