# pg_auth_mon

## Intro

PostgreSQL extension to store authentication attempts

This extension eases monitoring of login attempts to your
database. Postgres writes each login attempt to a log file, but it is
hard to identify through that information alone if your database
is under malicious activity. Maintaining separately information like the total number of successful login attempts, or a timestamp of the last failed login helps to answer questions like:
- when has a user successfully logged in for the last time ?
- has a user genuinely mistyped their password or has their username been
compromised?
- is there any particular time when a malicious role is active?

Once we have spot a suspicious activity, we may dig
deeper by using this information along with the log file to identify the
particular IP address etc.

## List of available GUC variables:

`pg_auth_mon.log_period` = 60 # dump pg_auth_mon content to Postgres log every 60 minutes (default: 0 meaning the feature is off)

## How to build and install:

```bash
$ sudo make install
$ bash -x test.sh # tests only
```

Note tests run against a vanilla Postgres installation that uses `md5` authentication method for everything;
that affects expected test results. Have a look into `test.sh` for Postgres test configuraiton.

Depending on one's installation, one may or may not need `sudo` in the above script.

## How to run it:

1. Add `shared_preload_libraries = 'pg_auth_mon'` to your `postgresql.conf`
2. Restart postgresql, for example `sudo systemctl restart postgresql@12-main.service`
3. ```sql
   create extension pg_auth_mon;
   select * from pg_auth_mon;```

## How to use:

The information is accessible in the `pg_auth_mon` view. Each user who attempts to login gets a tuple in this view with:
- user name. The username for a given `oid` is retrieved from the catalog's view `pg_roles` (hence username is `null` for deleted roles). All login attempts with an invalid username (for example, non-existing users) are summed up into a single tuple with the oid equal to zero and empty username. 
- total number of successful login attempts
- timestamp of the last successful login
- timestamp of the failed login
- total number of failed login attempts because of some conflict in hba file. Unfortuantely due to [a Postgres limitation](https://github.com/RafiaSabih/pg_auth_mon/issues/10) this field is currently always empty
- total number of authentication failures because of other issues. Keep in mind a login attempt by a role without the `LOGIN` attribute is *not* an authentication failure

The view does not store more specific information like the client's IP address or port; check Postgres log for that information. 
