# Install pgmoneta

This tutorial will show you how to do a simple installation of pgmoneta.

At the end of this tutorial you will have a backup of a PostgreSQL cluster,
and will be streaming Write-Ahead Log (WAL) to pgmoneta.

## Preface

This tutorial assumes that you have an installation of PostgreSQL 10+ and pgmoneta.

For RPM based distributions such as Fedora and RHEL you can add the
[PostgreSQL YUM repository](https://yum.postgresql.org/) and do the install via

```
dnf install -y postgresql10 postgresql10-server pgmoneta
```

## Initialize cluster

```
export PATH=/usr/pgsql-10/bin:$PATH
initdb /tmp/pgsql
```

(`postgres` user)

## Remove default access

Remove

```
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
host    replication     all             127.0.0.1/32            trust
host    replication     all             ::1/128                 trust
```

from `/tmp/pgsql/pg_hba.conf`

(`postgres` user)

## Add access for users and a database

Add

```
host    mydb             myuser          127.0.0.1/32            md5
host    mydb             myuser          ::1/128                 md5
host    postgres         repl            127.0.0.1/32            md5
host    postgres         repl            ::1/128                 md5
host    replication      repl            127.0.0.1/32            md5
host    replication      repl            ::1/128                 md5
```

to `/tmp/pgsql/pg_hba.conf`

Remember to check the value of `password_encryption` in `/tmp/pgsql/postgresql.conf`
to setup the correct authentication type.

(`postgres` user)

## Make sure that replication level is set

Check that

```
wal_level = replica
```

is set in `/tmp/pgsql/postgresql.conf` - or `logical`

(`postgres` user)

## Start PostgreSQL

```
pg_ctl  -D /tmp/pgsql/ start
```

(`postgres` user)

## Add users and a database

```
createuser -P myuser
createdb -E UTF8 -O myuser mydb
```

with `mypass` as the password.

Then

```
psql postgres
CREATE ROLE repl WITH LOGIN REPLICATION PASSWORD 'secretpassword';
\q
```

(`postgres` user)

## Verify access

For the user (standard) (using `mypass`)

```
psql -h localhost -p 5432 -U myuser mydb
\q
```

For the user (pgmoneta) (using `secretpassword`)

```
psql -h localhost -p 5432 -U repl postgres
\q
```

(`postgres` user)

## Add pgmoneta user

```
sudo su -
useradd -ms /bin/bash pgmoneta
passwd pgmoneta
exit
```

(`postgres` user)

## Create pgmoneta configuration

Switch to the pgmoneta user

```
sudo su -
su - pgmoneta
```

Add the master key and create vault

```
pgmoneta-admin master-key
pgmoneta-admin -f pgmoneta_users.conf -U repl -P secretpassword add-user
```

You have to choose a password for the master key - remember it !

Create the `pgmoneta.conf` configuration

```
cat > pgmoneta.conf
[pgmoneta]
host = *
metrics = 5001

base_dir = /home/pgmoneta/backup

compression = zstd

storage_engine = local

retention = 7

log_type = file
log_level = info
log_path = /tmp/pgmoneta.log

unix_socket_dir = /tmp/
pgsql_dir = /usr/pgsql-10/bin/

[primary]
host = localhost
port = 5432
user = repl
```

and press `Ctrl-D`

(`postgres` user)

## Create base directory

```
mkdir backup
```

(`pgmoneta` user)

## Start pgmoneta

```
pgmoneta -c pgmoneta.conf -u pgmoneta_users.conf
```

(`pgmoneta` user)

## Create a backup

In another terminal

```
pgmoneta-cli -c pgmoneta.conf backup primary
```

(`pgmoneta` user)

## View backup

In another terminal

```
pgmoneta-cli -c pgmoneta.conf details
```

(`pgmoneta` user)
