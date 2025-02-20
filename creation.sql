CREATE TABLE
  "BadTLD" ("TLD" TEXT PRIMARY KEY);

CREATE TABLE
  "ErrorLog" (
    "Event" SERIAL PRIMARY KEY,
    "Timestamp" TIMESTAMP
    WITH
      TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      "Domain" TEXT DEFAULT NULL,
      "Error" TEXT DEFAULT NULL
  );

CREATE TABLE
  "JunkWords" ("Keywords" TEXT PRIMARY KEY);

CREATE TABLE
  "MastodonDomains" (
    "Domain" TEXT PRIMARY KEY,
    "SoftwareVersion" TEXT DEFAULT NULL,
    "TotalUsers" INTEGER DEFAULT NULL,
    "ActiveUsersMonthly" INTEGER DEFAULT NULL,
    "Timestamp" TEXT DEFAULT NULL,
    "CVEPatch" BOOLEAN DEFAULT NULL,
    "Contact" TEXT DEFAULT NULL,
    "Source" TEXT DEFAULT NULL,
    "FullVersion" TEXT DEFAULT NULL
  );

CREATE TABLE
  "NoPeers" ("Domain" TEXT PRIMARY KEY);

CREATE TABLE
  "RawDomains" (
    "Domain" TEXT PRIMARY KEY,
    "Failed" INTEGER DEFAULT NULL,
    "Ignore" INTEGER DEFAULT NULL,
    "Errors" INTEGER DEFAULT NULL,
    "Reason" TEXT DEFAULT NULL,
    "NXDOMAIN" INTEGER DEFAULT NULL,
    "Robots" INTEGER DEFAULT NULL
  );

INSERT INTO
  "BadTLD" ("TLD")
VALUES
  ('gov'),
  ('mil'),
  ('su');

INSERT INTO
  "JunkWords" ("Keywords")
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