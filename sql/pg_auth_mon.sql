create role auth_super with superuser login password 'postgres';
create role auth_nologin with password 'postgres';
create role auth_test with login password 'wrongpassword';

create database testdb;

create extension pg_auth_mon;

--1.Successful Login attempt
\! PGPASSWORD=postgres psql -U auth_super -d testdb -c "select 1"
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%';

--2.Login attempt by invalid username
\! PGPASSWORD=postgres psql -U auth_blah -d testdb  -c "select 1"
select rolname, uid, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where uid = 0;

--3.Login attempt by username who is not allowed to login is not authentication failure
\! PGPASSWORD=postgres psql -U auth_nologin -d testdb -c "select 1"
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%';

--4.Login attempt by a valid user with a wrong password 
\! PGPASSWORD=postgres psql -U auth_test -d testdb -c "select 1"
select rolname, successful_attempts, total_hba_conflicts, other_auth_failures from pg_auth_mon where rolname like 'auth_%' order by rolname;

--Cleanup
drop role auth_nologin;
drop role auth_test;
drop database testdb;
drop role auth_super;
