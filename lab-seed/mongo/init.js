// Seeded by /docker-entrypoint-initdb.d on first startup.
// Mongo is started without auth (no MONGO_INITDB_ROOT_*) — anonymous reads
// over the network. The audit should flag both the no-auth listener AND
// the cleartext credentials sitting in `corp.secrets`.

db = db.getSiblingDB('corp');

db.secrets.insertMany([
  { service: 'gitea',  user: 'ci',      pass: 'ci-deploy-2024',
    note:  'CI deploy key, rotates yearly' },
  { service: 'tomcat', user: 'tomcat',  pass: 'tomcat',
    note:  'Manager creds, port 8080 — same on every host' },
  { service: 'redis',  user: '',        pass: '',
    note:  'No auth, do not expose externally' },
  { service: 'aws',    user: 'test',    pass: 'test',
    note:  'Backup IAM user; endpoint http://localstack:4566' },
  { service: 'mysql',  user: 'root',    pass: 'Summer2024!',
    note:  'appdb root — same as AD svc_backup, do not rotate independently' }
]);

db.users.insertMany([
  { email: 'alice@lab.local', password_hash: '$2b$10$abcdefghijklmnopqrstuv', role: 'admin' },
  { email: 'bob@lab.local',   password_hash: 'plaintext-bob',                role: 'user'  },
  { email: 'svc@lab.local',   password_hash: 'Summer2024!',                  role: 'admin' }
]);

db.sessions.insertOne({
  token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.lab-test-token.signature',
  user:  'admin@lab.local',
  expires_at: new Date(Date.now() + 86400000)
});
