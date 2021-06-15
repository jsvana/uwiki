CREATE TABLE pages (
  slug VARCHAR(256) NOT NULL PRIMARY KEY,
  owner_id INT NOT NULL,
  current_version INT NOT NULL DEFAULT 0,
  title VARCHAR(256),
  body TEXT
);
