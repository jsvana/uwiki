CREATE TABLE page_revisions (
  slug VARCHAR(256) NOT NULL PRIMARY KEY,
  editor_id INT NOT NULL,
  version INT NOT NULL DEFAULT 0,
  body TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_editor
    FOREIGN KEY(editor_id)
      REFERENCES users(id)
);
