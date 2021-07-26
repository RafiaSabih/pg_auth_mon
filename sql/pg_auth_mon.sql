create role auth_super with superuser login password 'postgres';
create role auth_nologin with password 'postgres';
create role auth_test with login password 'wrongpassword';
create role auth_to_be_deleted with login password 'foobar';
create role auth_to_be_renamed with login password 'postgres';


create database testdb;

create extension pg_auth_mon version '1.0';

--1.Successful Login attempt
\! PGPASSWORD=postgres psql -X -U auth_super -d testdb -c "select 1"
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%';

--2.Login attempt by invalid username
\! PGPASSWORD=postgres psql -X -U auth_blah -d testdb  -c "select 1" 2>&1 | sed 's/^.* FATAL: */FATAL: /'
select rolname, uid, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where uid = 0;

--3.Login attempt by username who is not allowed to login is not authentication failure
\! PGPASSWORD=postgres psql -X -U auth_nologin -d testdb -c "select 1" 2>&1 | sed 's/^.* FATAL: */FATAL: /'
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%';

--4.Login attempt by a valid user with a wrong password 
\! PGPASSWORD=postgres psql -X -U auth_test -d testdb -c "select 1" 2>&1 | sed 's/^.* FATAL: */FATAL: /'
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%' order by rolname;

--5. Test upgrade to version '1.1'
alter extension pg_auth_mon update to '1.1';
select extversion from pg_extension where extname = 'pg_auth_mon';
-- ensure the data from the previous version is still accessible
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%' order by rolname;

--6. Rolname is not empty for deleted users
\! PGPASSWORD=foobar psql -X -U auth_to_be_deleted -d testdb -c "select 1"
drop role auth_to_be_deleted;
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%' order by rolname;

--7. The rolname at the last login attempt (not the initial one) is shown when a role is renamed before deletion
\! PGPASSWORD=postgres psql -X -U auth_to_be_renamed -d testdb -c "select 1"
alter role auth_to_be_renamed rename to auth_renamed;
alter role auth_renamed with password 'postgres';
\! PGPASSWORD=postgres psql -X -U auth_renamed -d testdb -c "select 1"
drop role auth_renamed;
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%' order by rolname;


--Cleanup
drop role auth_nologin;
drop role auth_test;
drop role auth_super;
drop database testdb;
