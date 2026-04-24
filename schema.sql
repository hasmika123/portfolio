-- ============================================================
-- Supabase Database Schema
-- Project: portfolio-contact
-- Table: contact_messages
-- ============================================================

CREATE TABLE contact_messages (
  id           uuid                     NOT NULL DEFAULT gen_random_uuid(),
  name         text                     NOT NULL,
  email        text                     NOT NULL,
  subject      text,
  message      text                     NOT NULL,
  submitted_at timestamp with time zone DEFAULT now(),

  CONSTRAINT contact_messages_pkey PRIMARY KEY (id)
);

-- ============================================================
-- Notes:
-- Row Level Security (RLS) is DISABLED on this table.
-- The table accepts public INSERT from anonymous users via
-- the Supabase JS client (anon key). No per-user access
-- control is required since submissions are non-sensitive
-- contact form data.
--
-- To re-enable RLS and add a policy for public inserts:
--
--   ALTER TABLE contact_messages ENABLE ROW LEVEL SECURITY;
--
--   CREATE POLICY "Allow public inserts"
--     ON contact_messages
--     FOR INSERT
--     TO anon
--     WITH CHECK (true);
-- ============================================================
