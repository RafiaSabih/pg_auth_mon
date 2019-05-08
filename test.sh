#!bin/bash

version=$(postgres -V | sed -n 's/^.* \([1-9][0-9]*\(\.[0-9]*\)\{0,2\}\).*/\1/p')
version=${version%.*}

rm -fr test_cluster*
set -e
sudo chmod a+w /var/run/postgresql

readonly port=5440

function start_postgres() {
    postgres -D test_cluster$1 --port=$(($port+$1)) &
    max_attempts=0
    while ! pg_isready -h localhost -p $(($port+$1)) -d postgres; do
        [[ $((max_attempts++)) -lt 10 ]] && sleep 1 || exit 1
    done
}
 
function shutdown_clusters() {
    set +e
    pg_ctl -w -D test_cluster0 stop -mf
    pg_ctl -w -D test_cluster1 stop -mf
}

function create_cluster() {
    initdb test_cluster$1
    echo "local all all		 md5" >> test_cluster$1/pg_hba.conf
    echo "shared_preload_libraries = 'pg_auth_mon'" >> test_cluster$1/postgresql.conf

    start_postgres $1
}

create_cluster 0

PGPASSWORD=postgres psql -U none -d postgres
PGPASSWORD=postgres psql -U postgres -d postgres -c "CREATE EXTENSION pg_auth_mon"
PGPASSWORD=postgres psql -U postgres -d postgres -c "SELECT uid, successful_attempts, total_hba_conflicts, other_auth_failures FROM pg_auth_mon()"

shutdown_clusters
