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
particular IP address, etc.


## Under the hood

The extension stores login attempts in a dynamic hash table in shared
memory. The key for this hash table is the `oid` of a user. The hash table also contains per user:
- total number of successful login attempts
- timestamp of the last successful login
- timestamp of the failed login
- total number of failed login attempts because of some conflict in hba file
- total number of authentication failures because of other issues

The information is accessible for querying via the `pg_auth_mon` view. Each valid user who attempts to login gets a tuple in this view. All login attempts with an invalid user name are summed up into a single
tuple with the oid equal to zero. The view does not store more specific information like the client's IP address or port; check Postgres log for that information. The username for a given `oid` is retrieved from the catalog's view `pg_roles`.
