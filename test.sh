#!bin/bash

export PGPASSWORD=postgres
export PGDATA=test_cluster
export PGPORT=5440
export PGHOST=/tmp

function cleanup() {
    pg_ctl -w stop -mf
    rm -fr $PGDATA $pwfile
}

cleanup 2> /dev/null

set -e

readonly pwfile=$(tempfile)
echo -n $PGPASSWORD > $pwfile
initdb --pwfile=$pwfile --auth=md5

trap cleanup QUIT TERM EXIT

pg_ctl start -w -o "--shared_preload_libraries=pg_auth_mon --unix_socket_directories=$PGHOST"

make USE_PGXS=1 installcheck || diff -u expected/pg_auth_mon.out results/pg_auth_mon.out
