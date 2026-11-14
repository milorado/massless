-- Publish the complete release pointer in the same D1 update as its version.
-- NULL preserves existing R2 manifest.json sites until their next publish.
ALTER TABLE sites ADD COLUMN manifest_json TEXT;
