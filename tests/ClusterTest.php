<?php declare(strict_types=1);
require_once('CouchbaseTestCase.php');

use \Couchbase\Cluster;
use \Couchbase\ClusterOptions;
use \Couchbase\NetworkException;

class ClusterTest extends CouchbaseTestCase {
    function testBadHost() {
        $options = new ClusterOptions();
        $options->credentials($this->testUser, $this->testPassword);
        $this->expectException(NetworkException::class);
        new Cluster('couchbase://999.99.99.99', $options);
    }
}
