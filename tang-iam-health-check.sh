#!/bin/bash -e
test -z "${PORT}" && PORT=8000
sqlite3 /var/lib/sqlite/tang_bindings.db 'select * from bindings;'
curl -k --cert /tmp/server_bundle.pem --key /tmp/server.key "https://localhost:${PORT}/health"
