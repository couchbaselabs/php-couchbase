# Couchbase PHP Client

This library allows you to connect to a Couchbase cluster from PHP.
It is a native PHP extension and uses the very fast libcouchbase library to
handle communicating to the cluster over the Couchbase binary protocol.

[![Build Status](http://cbsdkbuilds.br19.com/buildStatus/icon?job=cb-php)](http://cbsdkbuilds.br19.com/job/cb-php/)


## Useful Links

Source - http://github.com/couchbaselabs/php-couchbase

Bug Tracker - http://www.couchbase.com/issues/browse/PCBC

Couchbase PHP Community - http://couchbase.com/communities/php


## Installing

This iteration of the Couchbase PHP client is not currently available via
PECL, and as such must be compiled manually in order to be used.  The extension
will become available via PECL once it leaves the DP phase.  Until then, you may
install by downloading a prebuilt binary of the DP available on couchbase.com
for the Windows platform, or by checking out the repository and building
it directly:

```bash
phpize
./configure --enable-couchbase
make && make install
```


## Introduction

Connecting to a Couchbase bucket is as simple as creating a new Connection
instance.  Once you are connect, you may execute any of Couchbases' numerous
operations against this connection.

Here is a simple example of instantiating a connection, setting a new document
into the bucket and then retrieving its contents:

```php
  $cluster = new CouchbaseCluster('192.168.7.26');
  $db = $cluster->openBucket('default');
  $db->upsert('testdoc', array('name'=>'Frank'));
  $res = $db->get('testdoc');
  var_dump($res->value);
  // array(1) {
  //   ["name"]=>
  //   string(5) "Frank"
  // }
```

### Version Support

As of March 2016, this extension supports PHP 5.x releases and is being ported
to PHP 7.  Contributions toward that update are welcome!  The work in progress
is posted at http://review.couchbase.org/#/c/58547/

## Documentation

An extensive documentation is available on the Couchbase website.  Visit our
[PHP Community](http://couchbase.com/communities/php) on
the [Couchbase](http://couchbase.com) website for the documentation as well as
numerous examples and samples.


## Source Control

The source code is available at
[https://github.com/couchbaselabs/php-couchbase](https://github.com/couchbaselabs/php-couchbase).

To execute our test suite, simply install and execute phpunit against your
checked out source code.


## License
Copyright 2016 Couchbase Inc.

Licensed under the Apache License, Version 2.0.

See
[LICENSE](https://github.com/couchbaselabs/php-couchbase/blob/master/LICENSE)
for further details.
