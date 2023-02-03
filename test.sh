#!/bin/bash

PG="$1"
if [ -n "$PG" ]; then
  PATH=/usr/lib/postgresql/$PG/bin:$PATH
fi

export PGPASSWORD=postgres
export PGDATA=test_cluster
export PGPORT=5440
export PGHOST=/tmp

function cleanup() {
    pg_ctl -w stop -mf
    rm -fr $PGDATA $pwfile
}

cleanup 2> /dev/null

set -ex

readonly pwfile=$(mktemp)
echo -n $PGPASSWORD > $pwfile
initdb --pwfile=$pwfile --auth=md5

trap cleanup QUIT TERM EXIT

pg_ctl start -w -o "--shared_preload_libraries=pg_auth_mon --unix_socket_directories=$PGHOST"

make USE_PGXS=1 installcheck || diff -u expected/pg_auth_mon.out results/pg_auth_mon.out

if grep -E '(ERROR|FATAL)' test_cluster/pg_log/postgresql.log | grep -Ev '(no COPY in progress|could not connect to|could not send|the database system is not yet accepting connections|database system is shutting|error reading result of streaming command|database system is starting up|log:noisia)'; then
  exit 1
fi
