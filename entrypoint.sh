#!/bin/bash
#
# Copyright 2023
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

db_command() {
  echo "$1" | mysql --user=root --password=redhat123
}

mysqld &
sleep 5
generate-signed-certificate.sh
db_command "UPDATE mysql.user SET host='%' WHERE user='root';" 2>/dev/null 1>/dev/null
db_command "grant all on db.* to 'root'@'127.0.0.1';" 2>/dev/null 1>/dev/null
db_command "CREATE DATABASE tang_bindings;" 2>/dev/null 1>/dev/null
db_command "USE tang_bindings; create table bindings (spiffe_id VARCHAR(255) NOT NULL, tang_workspace VARCHAR(255) NOT NULL);" 2>/dev/null 1>/dev/null
/usr/bin/tang-iam-proxy -dbUser root -dbPass redhat123 -httpUser jdoe -httpPass jdoe12345 -port 8000 -serverCert server_bundle.pem --serverKey server.key -tangServer TANG_SERVER_HERE
