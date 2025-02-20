CREATE TABLE
  bad_tld (tld TEXT PRIMARY KEY);

CREATE TABLE
  error_log (
    event SERIAL PRIMARY KEY,
    timestamp TIMESTAMP
    WITH
      TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      domain TEXT DEFAULT NULL,
      error TEXT DEFAULT NULL
  );

CREATE TABLE
  junk_words (keywords TEXT PRIMARY KEY);

CREATE TABLE
  mastodon_domains (
    domain TEXT PRIMARY KEY,
    software_version TEXT DEFAULT NULL,
    total_users INTEGER DEFAULT NULL,
    active_users_monthly INTEGER DEFAULT NULL,
    timestamp TEXT DEFAULT NULL,
    cve_patch BOOLEAN DEFAULT NULL,
    contact TEXT DEFAULT NULL,
    source TEXT DEFAULT NULL,
    full_version TEXT DEFAULT NULL
  );

CREATE TABLE
  no_peers (domain TEXT PRIMARY KEY);

CREATE TABLE
  raw_domains (
    domain TEXT PRIMARY KEY,
    failed BOOLEAN DEFAULT NULL,
    ignore BOOLEAN DEFAULT NULL,
    errors INTEGER DEFAULT NULL,
    reason TEXT DEFAULT NULL,
    nxdomain BOOLEAN DEFAULT NULL,
    norobots BOOLEAN DEFAULT NULL
  );

INSERT INTO
  bad_tld (tld)
VALUES
  ('gov'),
  ('mil'),
  ('su');

INSERT INTO
  junk_words (keywords)
VALUES
  ('activitypub-proxy.cf'),
  ('activitypub-troll.cf'),
  ('cf-ipfs.com'),
  ('elestio.app'),
  ('github.dev'),
  ('gitpod.io'),
  ('herokuapp.com'),
  ('lhr.life'),
  ('lhrtunnel.link'),
  ('ngrok-free.app'),
  ('ngrok.app'),
  ('ngrok.dev'),
  ('ngrok.io'),
  ('nope.rodeo'),
  ('serveo.net');