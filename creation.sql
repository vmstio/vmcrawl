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
  CREATE TABLE
    junk_words (
      keywords TEXT PRIMARY KEY,
      comments TEXT DEFAULT NULL
    );

CREATE TABLE
  mastodon_domains (
    domain TEXT PRIMARY KEY,
    software_version TEXT DEFAULT NULL,
    total_users INTEGER DEFAULT NULL,
    active_users_monthly INTEGER DEFAULT NULL,
    timestamp TIMESTAMP DEFAULT NULL,
    cve_patch BOOLEAN DEFAULT NULL,
    contact TEXT DEFAULT NULL,
    source TEXT DEFAULT NULL,
    full_version TEXT DEFAULT NULL,
    registration_date TIMESTAMP DEFAULT NULL
  );

CREATE TABLE
  no_peers (domain TEXT PRIMARY KEY);

CREATE TABLE
  patch_versions (
    software_version TEXT NULL,
    main BOOLEAN DEFAULT NULL,
    release BOOLEAN DEFAULT NULL,
    n_level INTEGER PRIMARY KEY,
    branch TEXT DEFAULT NULL
  );

CREATE TABLE
  eol_versions (software_version TEXT PRIMARY KEY);

CREATE TABLE
  raw_domains (
    domain TEXT PRIMARY KEY,
    failed BOOLEAN DEFAULT NULL,
    ignore BOOLEAN DEFAULT NULL,
    errors INTEGER DEFAULT NULL,
    reason TEXT DEFAULT NULL,
    nxdomain BOOLEAN DEFAULT NULL,
    norobots BOOLEAN DEFAULT NULL,
    baddata BOOLEAN DEFAULT NULL
  );

CREATE TABLE statistics (
    date DATE PRIMARY KEY,
    total_raw_domains INTEGER,
    total_failed_domains INTEGER,
    total_mastodon_domains INTEGER,
    total_ignored_domains INTEGER,
    total_nxdomains INTEGER,
    total_norobots INTEGER,
    total_baddata INTEGER,
    total_error_over INTEGER,
    total_error_under INTEGER,
    total_users INTEGER,
    total_active_users INTEGER,
    total_unique_versions INTEGER,
    total_main_instances INTEGER,
    total_release_instances INTEGER,
    total_previous_instances INTEGER,
    total_pending_eol_instances INTEGER,
    total_eol_instances INTEGER,
    total_main_patched_instances INTEGER,
    total_release_patched_instances INTEGER,
    total_previous_patched_instances INTEGER,
    total_pending_eol_patched_instances INTEGER,
    total_main_branch_users INTEGER,
    total_release_branch_users INTEGER,
    total_previous_branch_users INTEGER,
    total_pending_eol_branch_users INTEGER,
    total_eol_branch_users INTEGER,
    total_main_patched_users INTEGER,
    total_release_patched_users INTEGER,
    total_previous_patched_users INTEGER,
    total_pending_eol_patched_users INTEGER,
    total_active_main_branch_users INTEGER,
    total_active_release_branch_users INTEGER,
    total_active_previous_branch_users INTEGER,
    total_active_pending_eol_branch_users INTEGER,
    total_active_eol_branch_users INTEGER,
    total_active_main_patched_users INTEGER,
    total_active_release_patched_users INTEGER,
    total_active_previous_patched_users INTEGER,
    total_active_pending_eol_patched_users INTEGER
  );

INSERT INTO
  bad_tld (tld)
VALUES
  ('arpa'),
  ('gov'),
  ('mil'),
  ('su');

INSERT INTO
  patch_versions (software_version, main, release, n_level, branch)
VALUES
  ('4.4.0-alpha.2', TRUE, FALSE, -1, '4.4'),
  ('4.3.3', FALSE, TRUE, 0, '4.3'),
  ('4.2.15', FALSE, TRUE, 1, '4.2'),
  ('4.1.22', FALSE, TRUE, 2, '4.1');

INSERT INTO
  eol_versions (software_version)
VALUES
  ('4.0'),
  ('3'),
  ('2'),
  ('1');

INSERT INTO
  junk_words (keywords, comments)
VALUES
  ('activitypub-proxy.cf', NULL),
  ('activitypub-troll.cf', NULL),
  ('cf-ipfs.com', NULL),
  ('elestio.app', NULL),
  ('github.dev', NULL),
  ('gitpod.io', NULL),
  ('herokuapp.com', NULL),
  ('lhr.life', NULL),
  ('lhrtunnel.link', NULL),
  ('ngrok-free.app', NULL),
  ('ngrok.app', NULL),
  ('ngrok.dev', NULL),
  ('ngrok.io', NULL),
  ('nope.rodeo', NULL),
  ('serveo.net', NULL);