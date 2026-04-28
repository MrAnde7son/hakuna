Public Share — corp jumpbox notes

Files in this share:
  aws-creds.txt   — AWS creds for the corp-backups pipeline (default profile)
  README.txt      — this file

Operational notes (please don't move these — cron jobs reference them):
  - aws-creds.txt is read by /etc/cron.daily/backup on the jumpbox.
  - The DB account (appdb mysql, user 'root') reuses the same password as
    the AD service account `svc_backup`. Don't rotate one without the other.
  - For SSH to the jumpbox use lab / labpass on port 2222 (sudo enabled).
  - Tomcat manager (port 8080) creds are tomcat / tomcat — only used during
    deploys, but the page is reachable from inside the network.
