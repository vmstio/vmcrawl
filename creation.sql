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
    domain TEXT PRIMARY KEY CHECK (domain = LOWER(domain)),
    software_version TEXT DEFAULT NULL,
    active_users_monthly INTEGER DEFAULT NULL,
    timestamp TIMESTAMP DEFAULT NULL,
    full_version TEXT DEFAULT NULL,
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
    domain TEXT PRIMARY KEY CHECK (domain = LOWER(domain)),
    failed BOOLEAN DEFAULT NULL,
    ignore BOOLEAN DEFAULT NULL,
    errors INTEGER DEFAULT NULL,
    reason TEXT DEFAULT NULL,
    nxdomain BOOLEAN DEFAULT NULL,
    norobots BOOLEAN DEFAULT NULL,
    noapi BOOLEAN DEFAULT NULL,
    baddata BOOLEAN DEFAULT NULL,
    nodeinfo TEXT DEFAULT NULL,
    alias BOOLEAN DEFAULT NULL
  );

CREATE TABLE statistics (
    date DATE PRIMARY KEY,
    mau INTEGER,
    unique_versions INTEGER,
    main_instances INTEGER,
    latest_instances INTEGER,
    previous_instances INTEGER,
    deprecated_instances INTEGER,
    eol_instances INTEGER,
    main_patched_instances INTEGER,
    latest_patched_instances INTEGER,
    previous_patched_instances INTEGER,
    deprecated_patched_instances INTEGER,
    main_branch_mau INTEGER,
    latest_branch_mau INTEGER,
    previous_branch_mau INTEGER,
    deprecated_branch_mau INTEGER,
    eol_branch_mau INTEGER,
    main_patched_mau INTEGER,
    latest_patched_mau INTEGER,
    previous_patched_mau INTEGER,
    deprecated_patched_mau INTEGER
  );


CREATE TABLE nightly_versions (
    version VARCHAR(50),
    start_date DATE,
    end_date DATE
  );

CREATE TABLE
  dni (
    domain TEXT PRIMARY KEY,
    comment TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
  ('appspot.com', NULL),
  ('balena-devices.com', NULL),
  ('cf-ipfs.com', NULL),
  ('cloud-xip.com', NULL),
  ('deno.dev', NULL),
  ('devtunnels.ms', NULL),
  ('elestio.app', NULL),
  ('fly.dev', NULL),
  ('github.dev', NULL),
  ('gitpod.io', NULL),
  ('herokuapp.com', NULL),
  ('lhr.life', NULL),
  ('lhrtunnel.link', NULL),
  ('linodeusercontent.com', NULL),
  ('localhost.run', NULL),
  ('loca.lt', NULL),
  ('myterminus.com', NULL),
  ('netlify.app', NULL),
  ('ngrok.app', NULL),
  ('ngrok.dev', NULL),
  ('ngrok-free.app', NULL),
  ('ngrok-free.dev', NULL),
  ('ngrok.io', NULL),
  ('nope.rodeo', NULL),
  ('pages.dev', NULL),
  ('penginn.net', NULL),
  ('pikapod.net', NULL),
  ('serveo.net', NULL),
  ('spacehost.dev', NULL),
  ('srv.us', NULL),
  ('tunnelto.dev', NULL),
  ('vercel.app', NULL),
  ('wordpress.com', NULL),
  ('workers.dev', NULL),
  ('wpcomstaging.com', NULL);

INSERT INTO
  nightly_versions (version, start_date, end_date)
VALUES
  ('4.4.0-rc.1', '2025-07-02', '2025-07-02'),
  ('4.4.0-beta.2', '2025-06-18', '2025-07-01'),
  ('4.4.0-beta.1', '2025-06-05', '2025-06-17'),
  ('4.4.0-alpha.5', '2025-05-07', '2025-06-03'),
  ('4.4.0-alpha.4', '2025-03-14', '2025-05-06'),
  ('4.4.0-alpha.3', '2025-02-28', '2025-03-13'),
  ('4.4.0-alpha.2', '2025-01-17', '2025-02-27'),
  ('4.4.0-alpha.1', '2024-10-08', '2025-01-16'),
  ('4.3.0-rc.1', '2024-10-01', '2024-10-07'),
  ('4.3.0-beta.2', '2024-09-18', '2024-09-30'),
  ('4.3.0-beta.1', '2024-08-24', '2024-09-17'),
  ('4.3.0-alpha.5', '2024-07-05', '2024-08-23'),
  ('4.3.0-alpha.4', '2024-05-31', '2024-07-04'),
  ('4.3.0-alpha.3', '2024-02-17', '2024-05-30'),
  ('4.3.0-alpha.2', '2024-02-15', '2024-02-17'),
  ('4.3.0-alpha.1', '2024-01-30', '2024-02-14'),
  ('4.3.0-alpha.0', '2023-09-28', '2024-01-29'),
  ('4.5.0-alpha.1', '2025-07-03', '2029-08-05'),
  ('4.5.0-alpha.2', '2025-08-06', '2025-10-13'),
  ('4.5.0-beta.1', '2025-10-16', '2025-10-21'),
  ('4.5.0-alpha.3', '2025-10-14', '2025-10-15'),
  ('4.5.0-beta.2', '2025-10-22', '2025-10-29'),
  ('4.5.0-rc.1', '2025-10-30', '2025-10-31'),
  ('4.6.0-alpha.1', '2025-11-01', '2026-01-07'),
  ('4.6.0-alpha.2', '2026-01-08', '2026-01-20'),
  ('4.6.0-alpha.3', '2026-01-21', '2099-12-31');
-- Note: 4.2.x and earlier do not have nightly builds
