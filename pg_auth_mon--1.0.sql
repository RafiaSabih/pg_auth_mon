/* contrib/pg_auth_mon/pg_auth_mon--1.0--1.1.sql */
/*
 * Author:  rsabih
 * Created: Apr 8, 2019
 */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "CREATE EXTENSION pg_auth_mon" to load this file. \quit

/* Now define */
CREATE FUNCTION pg_auth_mon(
    OUT uid oid,
    OUT successful_attempts int,
    OUT last_successful_TS timestampTz,
    OUT total_hba_conflicts   int,
    OUT other_auth_failures    int,
    OUT last_failed_TS  timestampTz,
    OUT initial_rolename name
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE;

CREATE VIEW pg_auth_mon AS
  SELECT 
    (CASE WHEN pg_roles.rolname IS NULL THEN initial_rolename ELSE pg_roles.rolname END) AS rolname, 
    (pg_roles.rolname IS NULL) AS deleted, 
    successful_attempts, last_successful_TS, total_hba_conflicts, other_auth_failures, last_failed_TS
  FROM pg_auth_mon() LEFT JOIN pg_roles ON oid = uid;
