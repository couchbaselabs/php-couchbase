#!/usr/bin/env bash

#    Copyright 2020 Couchbase, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

PROJECT_ROOT="$( cd "$(dirname "$0"/..)" >/dev/null 2>&1 ; pwd -P )"

set -x
set -e

CB_VERSION=${CB_VERSION:-$(git describe | sed 's/^v//g')}
CB_PHP_PREFIX=${CB_PHP_PREFIX:-/usr}

CB_PHPDOC_PHAR=${CB_PHPDOC_PHAR:-"${PROJECT_ROOT}/build/phpdoc.phar"}
if [ ! -f "${CB_PHPDOC_PHAR}" ]
then
    curl -L -o "${CB_PHPDOC_PHAR}" https://github.com/phpDocumentor/phpDocumentor/releases/download/v3.1.2/phpDocumentor.phar
fi

cd ${PROJECT_ROOT}

PHP_EXECUTABLE="${CB_PHP_PREFIX}/bin/php"

if [ -d "${PROJECT_ROOT}/../couchbase-php-client/src" ]
then
    CB_EXTRA_ARGS="-d ${PROJECT_ROOT}/../couchbase-php-client/src"
fi

${PHP_EXECUTABLE} \
    ${CB_PHPDOC_PHAR} \
    -t ${PROJECT_ROOT}/build/couchbase-php-client-${CB_VERSION} \
    -d ${PROJECT_ROOT}/api \
    ${CB_EXTRA_ARGS}
