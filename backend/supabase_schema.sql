-- ============================================================
-- Zerofalse — Supabase Schema v2.0 PRODUCTION
-- Run: Supabase Dashboard → SQL Editor → Run
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL,
  slug             TEXT UNIQUE NOT NULL,
  plan             TEXT DEFAULT 'free' CHECK (plan IN ('free','starter','growth','enterprise')),
  scan_count_month INTEGER DEFAULT 0,
  scan_limit_month INTEGER DEFAULT 1000,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Users (linked to Clerk)
CREATE TABLE IF NOT EXISTS users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  clerk_user_id  TEXT UNIQUE NOT NULL,
  email          TEXT NOT NULL,
  full_name      TEXT,
  org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role           TEXT DEFAULT 'member' CHECK (role IN ('owner','admin','member')),
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- API Keys
CREATE TABLE IF NOT EXISTS api_keys (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  key_hash     TEXT UNIQUE NOT NULL,
  key_prefix   TEXT NOT NULL,
  is_active    BOOLEAN DEFAULT TRUE,
  total_calls  INTEGER DEFAULT 0,
  last_used_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Scan Events
CREATE TABLE IF NOT EXISTS scan_events (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  api_key_id        UUID REFERENCES api_keys(id) ON DELETE SET NULL,
  agent_id          TEXT NOT NULL,
  session_id        TEXT,
  caller_agent_id   TEXT,
  tool_name         TEXT,
  arguments         JSONB,
  decision          TEXT NOT NULL CHECK (decision IN ('allow','warn','block')),
  risk_score        FLOAT,
  severity          TEXT CHECK (severity IN ('critical','high','medium','low','info')),
  threat_type       TEXT,
  title             TEXT,
  description       TEXT,
  evidence          JSONB DEFAULT '[]',
  hint              TEXT,
  safe_alternatives JSONB DEFAULT '[]',
  pattern_id        TEXT,
  latency_ms        FLOAT,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_event_id  UUID REFERENCES scan_events(id) ON DELETE SET NULL,
  agent_id       TEXT,
  threat_type    TEXT,
  severity       TEXT CHECK (severity IN ('critical','high','medium','low')),
  title          TEXT,
  description    TEXT,
  status         TEXT DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved')),
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  updated_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Webhooks
CREATE TABLE IF NOT EXISTS webhooks (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  url        TEXT NOT NULL,
  events     JSONB DEFAULT '[]',
  secret     TEXT NOT NULL,
  is_active  BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Webhook Deliveries
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id  UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  success     BOOLEAN NOT NULL,
  status_code INTEGER,
  error       TEXT,
  attempts    INTEGER DEFAULT 1,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Row Level Security ────────────────────────────────────────────────────────
ALTER TABLE organizations      ENABLE ROW LEVEL SECURITY;
ALTER TABLE users              ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys           ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_events        ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts             ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks           ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;

-- Deny all access via anon/authenticated roles.
-- Backend uses service_role key which bypasses RLS.
CREATE POLICY "deny_anon_organizations"      ON organizations      FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_anon_users"              ON users              FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_anon_api_keys"           ON api_keys           FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_anon_scan_events"        ON scan_events        FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_anon_alerts"             ON alerts             FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_anon_webhooks"           ON webhooks           FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_anon_webhook_deliveries" ON webhook_deliveries FOR ALL TO anon, authenticated USING (false);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_users_clerk_id           ON users(clerk_user_id);
CREATE INDEX IF NOT EXISTS idx_users_org_id             ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash            ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_org             ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_org_time     ON scan_events(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_events_org_decision ON scan_events(org_id, decision, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_events_org_agent    ON scan_events(org_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_org_status        ON alerts(org_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup             ON alerts(org_id, threat_type, agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries       ON webhook_deliveries(webhook_id, created_at DESC);

-- ── Triggers ──────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

DO $$ BEGIN
  CREATE TRIGGER trg_org_updated_at    BEFORE UPDATE ON organizations    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TRIGGER trg_alerts_updated_at BEFORE UPDATE ON alerts           FOR EACH ROW EXECUTE FUNCTION update_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TRIGGER trg_keys_updated_at   BEFORE UPDATE ON api_keys         FOR EACH ROW EXECUTE FUNCTION update_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── RPC Functions ─────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION increment_org_scan_count(org_id_input UUID)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE organizations SET scan_count_month = scan_count_month + 1, updated_at = NOW()
  WHERE id = org_id_input;
END;$$;

CREATE OR REPLACE FUNCTION increment_api_key_calls(key_id_input UUID)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE api_keys SET total_calls = total_calls + 1, updated_at = NOW()
  WHERE id = key_id_input;
END;$$;

CREATE OR REPLACE FUNCTION reset_monthly_scan_counts()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE organizations SET scan_count_month = 0, updated_at = NOW();
END;$$;
-- Schedule via Supabase cron: 0 0 1 * * → SELECT reset_monthly_scan_counts();

-- ── Safe upgrade migration ────────────────────────────────────────────────────
DO $$ BEGIN
  ALTER TABLE api_keys     ADD COLUMN IF NOT EXISTS updated_at       TIMESTAMPTZ DEFAULT NOW();
  ALTER TABLE scan_events  ADD COLUMN IF NOT EXISTS hint              TEXT;
  ALTER TABLE scan_events  ADD COLUMN IF NOT EXISTS safe_alternatives JSONB DEFAULT '[]';
  ALTER TABLE scan_events  ADD COLUMN IF NOT EXISTS pattern_id        TEXT;
EXCEPTION WHEN others THEN NULL;
END $$;
