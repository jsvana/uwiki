CREATE TABLE pages (
  slug VARCHAR(256) NOT NULL PRIMARY KEY,
  owner_id INT NOT NULL,
  current_version INT NOT NULL DEFAULT 0,
  title VARCHAR(256),
  body TEXT,
  rendered_body TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP,
  CONSTRAINT fk_owner
    FOREIGN KEY(owner_id)
      REFERENCES users(id)
);
