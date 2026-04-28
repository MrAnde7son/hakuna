-- Seeded by docker-entrypoint-initdb.d on first startup.
-- Root password is set via MYSQL_ROOT_PASSWORD env (matches LDAP svc_backup).

CREATE DATABASE IF NOT EXISTS appdb;
USE appdb;

CREATE TABLE IF NOT EXISTS users (
  id        INT AUTO_INCREMENT PRIMARY KEY,
  email     VARCHAR(128) NOT NULL,
  password  VARCHAR(128) NOT NULL,
  is_admin  TINYINT(1)   NOT NULL DEFAULT 0
);

INSERT INTO users (email, password, is_admin) VALUES
  ('alice@lab.local', 'Password1',          0),
  ('bob@lab.local',   'bob',                0),
  ('admin@lab.local', 'admin',              1),
  ('svc@lab.local',   'Summer2024!',        1);

CREATE TABLE IF NOT EXISTS secrets (
  id        INT AUTO_INCREMENT PRIMARY KEY,
  service   VARCHAR(64) NOT NULL,
  username  VARCHAR(64),
  password  VARCHAR(128),
  notes     TEXT
);

INSERT INTO secrets (service, username, password, notes) VALUES
  ('ssh-jumpbox', 'lab',   'labpass',     'Bastion at ssh:2222 (lab account, sudo enabled)'),
  ('aws-backup',  'test',  'test',        'IAM creds for nightly DB dump to s3://corp-backups (LocalStack)'),
  ('snmp',        '',      'public',      'v2c read community for site routers'),
  ('tomcat',      'tomcat','tomcat',      'Tomcat manager (port 8080) — used by deploy job'),
  ('mongo',       '',      '',            'No auth, internal network only');

-- A least-privileged app user that the webapp would use in real life.
CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'app123';
GRANT SELECT, INSERT, UPDATE ON appdb.* TO 'app'@'%';
FLUSH PRIVILEGES;
