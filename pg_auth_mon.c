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

Datum		pg_auth_mon(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pg_auth_mon);

PG_MODULE_MAGIC;

extern void _PG_init(void);
extern void _PG_fini(void);

#define AUTH_MON_COLS  7
#define AUTH_MON_HT_SIZE       1024

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
	NameData	user_name;
}				auth_mon_rec;

/* LWlock to mange the reading and writing the hash table. */
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

/* Hash table in the shared memory */
static HTAB *auth_mon_ht;

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

	/*
	 * Create or attach to the shared memory state, including hash table
	 */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

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
	 * exit hook to dump the statistics to disk.
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
	auth_mon_ht = NULL;

	return;
}

/*
 * Estimate shared memory space needed.
 */
static Size
fai_memsize(void)
{
	return hash_estimate_size(AUTH_MON_HT_SIZE, sizeof(auth_mon_rec));

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
		strcpy(fai->user_name.data, "dummy_user");
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

	LWLockRelease(auth_mon_lock);
}

/*
 * This is called when user requests the pg_auth_mon view.
 */
Datum
pg_auth_mon(PG_FUNCTION_ARGS)
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

	tupstore = tuplestore_begin_heap(true, false, work_mem);

	MemoryContextSwitchTo(oldcontext);

	LWLockAcquire(auth_mon_lock, LW_SHARED);

	hash_seq_init(&status, auth_mon_ht);
	while ((auth_mon_ht != NULL) && (entry = hash_seq_search(&status)) != NULL)
	{
		Datum		values[AUTH_MON_COLS];
		bool		nulls[AUTH_MON_COLS] = {0};
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
			nulls[i] = true;
		else
			values[i] = TimestampTzGetDatum(entry->last_failed_attempt_at);

		values[i++] = NameGetDatum(&(entry->user_name));
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
	ClientAuthentication_hook = auth_monitor;

}
