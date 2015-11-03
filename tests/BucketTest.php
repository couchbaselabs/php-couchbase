<?php
require_once('CouchbaseTestCase.php');

class BucketTest extends CouchbaseTestCase {

    /**
     * @test
     * Test that connections with invalid details fail.
     */
    function testBadPass() {
        $h = new CouchbaseCluster($this->testDsn);

        $this->wrapException(function() use($h) {
            $h->openBucket('default', 'bad_pass');
        }, 'CouchbaseException', 2);
    }

    /**
     * @test
     * Test that connections with invalid details fail.
     */
    function testBadBucket() {
        $h = new CouchbaseCluster($this->testDsn);

        $this->wrapException(function() use($h) {
            $h->openBucket('bad_bucket');
        }, 'CouchbaseException', 25);
    }

}
