CREATE TABLE images (
  slug VARCHAR(256) NOT NULL PRIMARY KEY,
  owner_id INT NOT NULL,
  extension VARCHAR(8) NOT NULL,
  alt_text VARCHAR(512)
);
