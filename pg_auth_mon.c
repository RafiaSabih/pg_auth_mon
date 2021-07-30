/* -------------------------------------------------------------------------
 *
 * pg_auth_mon.c
 *
 * Copyright (c) 2010-2019, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		contrib/pg_auth_mon/pg_auth_mon.c
 * -------------------------------------------------------------------------
 */
#include "postgres.h"


#include <limits.h>

#include "libpq/auth.h"
#include "libpq/libpq-be.h"
#include "port.h"
#include "miscadmin.h"
#include "access/hash.h"
#include "storage/lwlock.h"
#include "storage/ipc.h"
#include "storage/shmem.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/tuplestore.h"
#include "utils/timestamp.h"
#include "utils/acl.h"
#include "catalog/pg_authid.h"
#include "funcapi.h"
#include "c.h"
#include "utils/builtins.h"

Datum		pg_auth_mon(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pg_auth_mon);
PG_FUNCTION_INFO_V1(pg_auth_mon_1_1);

PG_MODULE_MAGIC;

extern void _PG_init(void);
extern void _PG_fini(void);

/* Number of output arguments (columns) for various API versions */
#define PG_AUTH_MON_COLS_V1_0  6
#define PG_AUTH_MON_COLS_V1_1  7
#define PG_AUTH_MON_COLS       7 /* max of the above */

#define AUTH_MON_HT_SIZE       1024

/*
 * Version number to support older versions of extension's objects
 */
typedef enum pgauthmonVersion
{
	PG_AUTH_MON_V1_0 = 0,
	PG_AUTH_MON_V1_1,
} pgauthmonVersion;

/*
 * A record for a login attempt.
 */
typedef struct auth_mon_rec
{
	Oid			key;
	int			total_successful_attempts;
	TimestampTz last_successful_login_at;
	TimestampTz last_failed_attempt_at;
	int			total_hba_conflicts;
	int			other_auth_failures;
	NameData	rolename_at_last_login_attempt;
}				auth_mon_rec;

/* LWlock to manage the reading and writing the hash table. */
#if PG_VERSION_NUM < 90400
LWLockId	auth_mon_lock;
#else
LWLock	   *auth_mon_lock;
#endif

/* Original Hook */
static ClientAuthentication_hook_type original_client_auth_hook = NULL;

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

static void fai_shmem_shutdown(int code, Datum arg);
static Datum pg_auth_mon_internal(PG_FUNCTION_ARGS, pgauthmonVersion api_version);

/* Hash table in the shared memory */
static HTAB *auth_mon_ht;

/* timestamp in shared memory used to limit the frequency of logging pg_auth_mon data */
static TimestampTz *last_log_timestamp;

static void fai_shmem_shutdown(int code, Datum arg);

static void log_pg_auth_mon_data(void);

/*
 * shmem_startup hook: allocate and attach to shared memory,
 */
static void
fai_shmem_startup(void)
{
	HASHCTL		info;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	auth_mon_ht = NULL;
	last_log_timestamp = NULL;

	/*
	 * Create or attach to the shared memory state, including hash table
	 */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	last_log_timestamp = ShmemAlloc(sizeof(TimestampTz));
	*last_log_timestamp = GetCurrentTimestamp();

	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(Oid);
	info.entrysize = sizeof(auth_mon_rec);
#if PG_VERSION_NUM > 100000
	info.hash = uint32_hash;

	auth_mon_ht = ShmemInitHash("auth_mon_hash",
								AUTH_MON_HT_SIZE, AUTH_MON_HT_SIZE,
								&info,
								HASH_ELEM | HASH_FUNCTION);
#else
	auth_mon_ht = ShmemInitHash("auth_mon_hash",
								AUTH_MON_HT_SIZE, AUTH_MON_HT_SIZE,
								&info,
								HASH_ELEM);
#endif
#if PG_VERSION_NUM < 90600
	auth_mon_lock = LWLockAssign();
#else
	auth_mon_lock = &(GetNamedLWLockTranche("auth_mon_lock"))->lock;
#endif
	LWLockRelease(AddinShmemInitLock);

	/*
	 * If we're in the postmaster (or a standalone backend...), set up a shmem
	 * exit hook to dump the authentication statistics to disk.
	 */
	if (!IsUnderPostmaster)
		on_shmem_exit(fai_shmem_shutdown, (Datum) 0);
}

/*
 * shmem_shutdown hook
 *
 * Note: we don't bother with acquiring lock, because there should be no
 * other processes running when this is called.
 */
static void
fai_shmem_shutdown(int code, Datum arg)
{

	log_pg_auth_mon_data();

	last_log_timestamp = NULL;
	auth_mon_ht = NULL;

	return;
}

/*
 * Write content of the `pg_auth_mon` to regular Postgres log to make it searchable later. 
 * 
 */
static void log_pg_auth_mon_data(){

	HASH_SEQ_STATUS status;
	auth_mon_rec *entry;
	const char *last_successful_login_at;
	const char *last_failed_attempt_at;

	LWLockAcquire(auth_mon_lock, LW_SHARED);

	hash_seq_init(&status, auth_mon_ht);
	while ((auth_mon_ht != NULL) && (entry = hash_seq_search(&status)) != NULL)
	{

		// XXX beware timestamptz_to_str uses the same static buffer to store results of all calls
		last_successful_login_at = entry->last_successful_login_at == 0 ? "0" : timestamptz_to_str(entry->last_successful_login_at);
		last_failed_attempt_at = entry->last_failed_attempt_at == 0 ? "0" : timestamptz_to_str(entry->last_failed_attempt_at);

		// XXX for already deleted users we log outdated oids here
		ereport(LOG, (errmsg("pg_auth_mon entry for user oid : %d rolename_at_last_login_attempt: %s total_successful_attempts: %d; last_successful_login_at: %s; last_failed_attempt_at: %s; total_hba_conflicts: %d; other_auth_failures: %d", 
						entry->key,
						entry->rolename_at_last_login_attempt.data,
						entry->total_successful_attempts,
						last_successful_login_at, last_failed_attempt_at,
						entry->total_hba_conflicts, entry->other_auth_failures))); 
	}

	LWLockRelease(auth_mon_lock);

}

/*
 * Estimate shared memory space needed.
 */
static Size
fai_memsize(void)
{
	Size size;

	size = MAXALIGN(sizeof(TimestampTz));
	size = add_size(size, hash_estimate_size(AUTH_MON_HT_SIZE, sizeof(auth_mon_rec)));
	return size;

}

/*
 * Monitor the authentication attempt here.
 * If the entry for this user does not exist then create one, otherwise update
 * the required values.
 */
static void
auth_monitor(Port *port, int status)
{
	auth_mon_rec *fai;
	Oid			key;
	bool		found = false,
				hba_reject = false,
				fail = false;

	int waittime = 1000 * 60 * 60 * 24; // log at most once in an day
	TimestampTz now = GetCurrentTimestamp();

	/*
	 * Any other plugins which use ClientAuthentication_hook.
	 */
	if (original_client_auth_hook)
		(*original_client_auth_hook) (port, status);

	/* Nothing to do */
	if (status == STATUS_EOF)
		return;

	key = get_role_oid((const char *) (port->user_name), true);
	/*
	 * A general case of failed attempt is when the status is not STATUS_OK.
	 * However, also consider the case when user-oid is invalid. Because it
	 * might get missed if authentication method is trust.
	 */
	fail = (status != STATUS_OK) || !OidIsValid(key);

	hba_reject = (port->hba->auth_method == uaReject) ||
		(port->hba->auth_method == uaImplicitReject);

	LWLockAcquire(auth_mon_lock, LW_EXCLUSIVE);

	fai = (auth_mon_rec *) hash_search(auth_mon_ht, &key, HASH_ENTER_NULL,
									   &found);

	if (!found)
	{
		fai->key = key;
		memset(&fai->total_successful_attempts, 0, sizeof(auth_mon_rec)
			   - offsetof(auth_mon_rec, total_successful_attempts));
		/*
		 * We use InvalidOid to aggregate login attempts
		 * of non-existing users. For them it makes no sense
		 * to persist any particular rolename, so we leave 
		 * rolename_at_last_login_attempt blank.
	 	 */
		if (key != InvalidOid) {
			namestrcpy(&fai->rolename_at_last_login_attempt, port->user_name);
		}
	} else {
		/*
		 *  The role was renamed between two consecutive login attempts.
		 */
		if (namestrcmp(&fai->rolename_at_last_login_attempt,port->user_name) != 0){
			namestrcpy(&fai->rolename_at_last_login_attempt, port->user_name);
		}
	}

	/*
	 * Increment the respective counters.
	 */
	if (fail)
	{
		if (hba_reject)
			fai->total_hba_conflicts += 1;
		else
			fai->other_auth_failures += 1;

		/* Always update the timestamp for last failed attempt. */
		fai->last_failed_attempt_at = GetCurrentTimestamp();
	}
	else
	{
		fai->total_successful_attempts += 1;

		/* Always update the timestamp for the last successful login */
		fai->last_successful_login_at = GetCurrentTimestamp();
	}

	if ((TimestampDifferenceExceeds(*last_log_timestamp, now, waittime))) {
		*last_log_timestamp = now;
		LWLockRelease(auth_mon_lock);
		log_pg_auth_mon_data();
		return;
	}

	LWLockRelease(auth_mon_lock);
}


/*
 * Entry point for the pg_auth_mon v 1.0
 */
Datum
pg_auth_mon(PG_FUNCTION_ARGS)
{
	pg_auth_mon_internal(fcinfo, PG_AUTH_MON_V1_0);

	return (Datum) 0;
}

Datum
pg_auth_mon_1_1(PG_FUNCTION_ARGS)
{
	pg_auth_mon_internal(fcinfo, PG_AUTH_MON_V1_1);

	return (Datum) 0;
}


/*
 * Retrieve authentication statistics for the pg_auth_mon view.
 *
 * The SQL API of this function has changed in version 1.1, and may change again in the future. 
 *
 * We support older APIs in case a newer version of this loadable module 
 * is being used with an old SQL declaration of the function.
 * That is, Postgres starts with the new pg_auth_mon.so, but "ALTER EXTENSION pg_auth_mon UPDATE" wasn't executed yet. 
 * It is a typical scenario we see during the rolling upgrade: a replica is running with the new .so file, but the primary with the old one.
 *
 * The expected API version is identified by embedding it in the C name of the
 * function except for the version 1.0
 * 
 * Modeled after pg_stat_statements
 */
Datum
pg_auth_mon_internal(PG_FUNCTION_ARGS, pgauthmonVersion api_version)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	HASH_SEQ_STATUS status;
	auth_mon_rec *entry;

	/* hash table must exist already */
	if (!auth_mon_ht)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_auth_mon must be loaded via shared_preload_libraries")));

	/* Switch into long-lived context to construct returned data structures */
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	/* Build a tuple descriptor for our result type */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	/* safety check for the expected number of arguments */
	switch (tupdesc->natts){
		case PG_AUTH_MON_COLS_V1_0:
			if (api_version != PG_AUTH_MON_V1_0)
				elog(ERROR, "incorrect number of output arguments");
			break;
		case PG_AUTH_MON_COLS_V1_1:
			if (api_version != PG_AUTH_MON_V1_1)
				elog(ERROR, "incorrect number of output arguments");
			break;
		default:
			elog(ERROR, "incorrect number of output arguments");
	}

	tupstore = tuplestore_begin_heap(true, false, work_mem);

	MemoryContextSwitchTo(oldcontext);

	LWLockAcquire(auth_mon_lock, LW_SHARED);

	hash_seq_init(&status, auth_mon_ht);
	while ((auth_mon_ht != NULL) && (entry = hash_seq_search(&status)) != NULL)
	{
		Datum		values[PG_AUTH_MON_COLS];
		bool		nulls[PG_AUTH_MON_COLS] = {0};
		int			i = 0;

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		values[i++] = ObjectIdGetDatum(entry->key);
		values[i++] = Int32GetDatum(entry->total_successful_attempts);

		/*
		 * If there is no successful login yet, then let the corresponding
		 * timestamp be null.
		 */
		if (entry->total_successful_attempts == 0)
			nulls[i++] = true;
		else
			values[i++] = TimestampTzGetDatum(entry->last_successful_login_at);
		values[i++] = Int32GetDatum(entry->total_hba_conflicts);
		values[i++] = Int32GetDatum(entry->other_auth_failures);

		/*
		 * If there is no failed login yet, then let the respective timestamp
		 * be null.
		 */
		if (entry->total_hba_conflicts == 0 &&
			entry->other_auth_failures == 0)
			nulls[i++] = true;
		else
			values[i++] = TimestampTzGetDatum(entry->last_failed_attempt_at);

		if (api_version >= PG_AUTH_MON_V1_1) {
			values[i] = NameGetDatum(&entry->rolename_at_last_login_attempt);
		}

		Assert(i == (api_version == PG_AUTH_MON_V1_0 ? PG_AUTH_MON_COLS_V1_0 :
				api_version == PG_AUTH_MON_V1_1 ? PG_AUTH_MON_COLS_V1_1 :
				-1 /* fail if the assert is not updated in the new version */ ));

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}



	LWLockRelease(auth_mon_lock);

	/* clean up and return the tuplestore */
	tuplestore_donestoring(tupstore);

	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	return (Datum) 0;
}

/*
 * Module Load Callback
 */
void
_PG_init(void)
{
	/*
	 * Request additional shared resources.  (These are no-ops if we're not in
	 * the postmaster process.)  We'll allocate or attach to the shared
	 * resources in *_shmem_startup().
	 */
	RequestAddinShmemSpace(fai_memsize());
#if PG_VERSION_NUM < 90600
	RequestAddinLWLocks(1);
#else
	RequestNamedLWLockTranche("auth_mon_lock", 1);
#endif

	/* Install Hooks */
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = fai_shmem_startup;

	original_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = auth_monitor;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hooks. */
	shmem_startup_hook = prev_shmem_startup_hook;
	ClientAuthentication_hook = original_client_auth_hook;

}
