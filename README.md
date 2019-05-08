# pg_auth_mon

PostgreSQL extension to store authentication attempts

The goal of this extension is to ease monitoring of login attempts to your
database. Although each failed login is written to database log file, but it is
not straightforward to identify through that information alone if your database
is under some malicious intents. However, if the information like total failed
as well as successful login attempts, timestamp of last failed and successful
login are maintained individually, then we can easily answer questions like,
- if the user genuinely mistyped their password or their username is being
compromised?
- if there is any particular time when the malicious user/application is active?

Once we have identified that there is a suspicious activity going on, we may dig
deeper by using this information along with the log file to identify the
particular IP address, etc.

One can view this view after creating the extension pg_auth_mon.

Under the hood:
All the login attempts are stored in a dynamic hash table maintained in shared
memory. The key for this hash table is the oid of user. Rest of the information
in this hash table are
- total number of successful attempts
- last timestamp of successful login
- last time of failed login attempt
- total number of failed login attempts because of some conflict in hba file
- total number of authentication failures because of other issues

Each valid user who attempts the login gets a tuple in this view. However, all
the attempts of login via some invalid user names are summed up in a single
tuple, with its oid being zero. More particular information like the username,
client IP address or port, etc. are not saved in this view, as they are  in the
log file. The username for a given oid can be retrieved from the system table
-- pg_roles.
