# Couchbase PHP Client

[![license](https://img.shields.io/github/license/couchbase/php-couchbase?color=brightgreen)](https://opensource.org/licenses/Apache-2.0)
[![jenkins](https://img.shields.io/jenkins/build?jobUrl=http%3A%2F%2Fsdk.jenkins.couchbase.com%2Fjob%2Fphp%2Fjob%2Fsdk%2Fjob%2Fphp-nightly%2F&label=jenkins)](http://sdk.jenkins.couchbase.com/job/php/job/sdk/job/php-nightly/)

This library allows you to connect to a Couchbase cluster from PHP.
It is a native PHP extension and uses the very fast libcouchbase library to
handle communicating to the cluster over the Couchbase binary protocol.
It supports 5.x and 7.x releases of PHP interpreter.

## Useful Links

* Source - https://github.com/couchbase/php-couchbase
* Bug Tracker - https://www.couchbase.com/issues/browse/PCBC
* Couchbase PHP Community - https://forums.couchbase.com/c/php-sdk
* Documentation - https://docs.couchbase.com/php-sdk/current/hello-world/start-using-sdk.html
* PECL - https://pecl.php.net/package/couchbase
* Packages - https://docs.couchbase.com/php-sdk/current/project-docs/sdk-release-notes.html
* Snapshots - http://sdk.jenkins.couchbase.com/job/php/job/sdk/job/php-win-scripted-build-pipeline/lastSuccessfulBuild/artifact/


## Installing

The target system should have libcouchbase installed. Detailed guide and links to the most recent versions
located here: https://docs.couchbase.com/c-sdk/current/project-docs/sdk-release-notes.html

### PECL

Couchbase PHP client generally available through PECL: http://pecl.php.net/package/couchbase

```bash
pecl install couchbase
```

### Binary packages

RPM package for Fedora available in official repository, its name is [php-pecl-couchbase2](https://apps.fedoraproject.org/packages/php-pecl-couchbase2).

```bash
dnf install php-pecl-couchbase2
```

RPM package for RHEL and CentOS linux available on [Remi's repository](https://rpms.remirepo.net/).

```bash
yum install php-pecl-couchbase2
```

Additionally Windows builds available from [Release Notes and Archives](http://developer.couchbase.com/server/other-products/release-notes-archives/php-sdk) page.

On MacOS platform, the library could be installed via Homebrew:

```bash
brew tap homebrew/homebrew-php
brew install php70-couchbase # or other version instead of 70 (PHP 7.0)
```

### Build from sources

If you are going to prepare patches, or just need to install the most recent
version from git, make sure you have PHP development tools and headers
installed, and run the following commands:

```bash
git clone https://github.com/couchbase/php-couchbase.git
cd php-couchbase
phpize
./configure --with-couchbase
make && make install
```

## Introduction

Connecting to a Couchbase bucket is as simple as creating a new Connection
instance.  Once you are connect, you may execute any of Couchbases' numerous
operations against this connection.

Here is a simple example of instantiating a connection, setting a new document
into the bucket and then retrieving its contents:

```php
$cluster = new \Couchbase\Cluster('localhost');
$db = $cluster->bucket('default');
$db->upsert('testdoc', array('name'=>'Frank'));
$res = $db->get('testdoc');
var_dump($res->value);
// array(1) {
//   ["name"]=>
//   string(5) "Frank"
// }
```

## Documentation

An extensive documentation is available on the Couchbase website.  Visit our
[PHP Community](https://forums.couchbase.com/c/php-sdk) on
the [Couchbase](http://developer.couchbase.com/documentation/server/current/sdk/php/start-using-sdk.html) website for the documentation as well as
numerous examples and samples.


To build PHP API reference, phpDocumentor 3.0.0+ have to be installed

    curl -L -o/tmp/phpdoc.phar curl https://github.com/phpDocumentor/phpDocumentor/releases/download/v3.0.0-rc/phpDocumentor.phar
    php /tmp/phpdoc.phar -t /tmp/output -d api/

The following steps assume that current directory is the root of this repository:

    ver=$(git describe | sed 's/^v//')
    rm -rf couchbase-php-client-$ver
    php /tmp/phpdoc.phar -t couchbase-php-client-$ver -d api/

After that all reference documentation will be stored in couchbase-php-client-3.0.0, if current tag is 3.0.0.

## Source Control

The source code is available at
[https://github.com/couchbase/php-couchbase](https://github.com/couchbase/php-couchbase).

To execute our test suite, simply install and execute phpunit against your
checked out source code. Tests assume that you have Couchbase Server with
default bucket running on localhost (otherwise use environment variable
`CB_DSN`, `CB_ADMIN_USER`, `CB_ADMIN_PASSWORD`, `CB_BUCKET`, `CB_USER`,
`CB_PASSWORD`. E.g. `CB_DSN=couchbase://192.168.1.42/ CB_BUCKET=travel-sample`).

```bash
curl -L https://phar.phpunit.de/phpunit.phar > ~/bin/phpunit
chmod a+x ~/bin/phpunit
# or just 'dnf install php-phpunit-PHPUnit' on Fedora 24+

phpunit tests/
```

Integration tests require some prerequisites, so once they met, you can run integration
tests with:

```bash
phpunit integration/
```

It is also possible to run tests using [CouchbaseMock](https://github.com/couchbase/CouchbaseMock):

```bash
CB_MOCK=1 phpunit tests/
```

Server version guard might be specified by `CB_VERSION` (default is `4.6`). The tests which depend on functionality,
which is not supported by `CB_VERSION`, will be skipped automatically.


## License

The library is available as open source under the terms of the [Apache2 License](https://opensource.org/licenses/Apache-2.0).

    Copyright 2016-2020 Couchbase, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
