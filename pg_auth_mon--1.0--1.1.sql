/* contrib/pg_auth_mon/pg_auth_mon--1.0--1.1.sql */
/*
 * Author:  rsabih
 * Created: Apr 8, 2019
 */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "CREATE EXTENSION pg_auth_mon" to load this file. \quit

-- re-create both the function and the view to add info about rolenames of deleted users
ALTER EXTENSION pg_auth_mon DROP FUNCTION pg_auth_mon();
DROP FUNCTION IF EXISTS pg_auth_mon();

CREATE FUNCTION pg_auth_mon(
    OUT uid oid,
    OUT successful_attempts int,
    OUT last_successful_TS timestampTz,
    OUT total_hba_conflicts   int,
    OUT other_auth_failures    int,
    OUT last_failed_TS  timestampTz,
    OUT rolename_at_last_login_attempt name
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE;

DROP VIEW IF EXISTS pg_auth_mon;
CREATE VIEW pg_auth_mon AS
  SELECT
    COALESCE(pg_roles.rolname, rolename_at_last_login_attempt) AS rolname, 
    (pg_roles.rolname IS NULL) AS deleted, 
    uid, successful_attempts, last_successful_TS, total_hba_conflicts, other_auth_failures, last_failed_TS
  FROM pg_auth_mon() LEFT JOIN pg_roles ON oid = uid;
