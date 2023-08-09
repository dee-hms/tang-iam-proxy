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

# Only copy database skeleton in case no database exist (fresh deployment)
test -f /var/lib/sqlite/tang_bindings.db || cp -rfv /usr/bin/tang_bindings.db /var/lib/sqlite
pushd /tmp || exit 1
cp -v /usr/bin/server_bundle.pem .
cp -v /usr/bin/server.key .
# Uncomment sleep to connect and check tang iam proxy
# sleep 3600
/usr/bin/tang-iam-proxy -httpUser jdoe -httpPass jdoe123 -port 8000 -serverCert server_bundle.pem --serverKey server.key -tangServer env-ephemeral-nfi4y5-5lu5yqrv.apps.c-rh-c-eph.8p0c.p1.openshiftapps.com -verbose
