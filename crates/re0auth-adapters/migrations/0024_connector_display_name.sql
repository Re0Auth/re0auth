-- Display-only label for a connector. The id stays the URL segment and the
-- binding key, so renaming the provider never touches stored bindings.
ALTER TABLE connectors ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
