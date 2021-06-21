<?php declare(strict_types=1);

require_once('CouchbaseTestCase.php');

class ExpiryTest extends CouchbaseTestCase {

    function defaultCollection() {
        $options = new \Couchbase\ClusterOptions();
        $options->credentials($this->testUser, $this->testPassword);
        $h = new \Couchbase\Cluster($this->testDsn, $options);
        $b = $h->bucket($this->testBucket);
        $this->setTimeouts($b);
        return $b->defaultCollection();
    }

    function testGetWithExpiryTime() {
        if ($this->usingMock()) {
            $this->markTestSkipped('Subdocument request to fetch time is not supported by CouchbaseMock.jar');
        }
        $c = $this->defaultCollection();
        $key = $this->makeKey('documentWithExpiry');

        $now = new DateTimeImmutable();

        $options = new \Couchbase\UpsertOptions();
        $options->expiry(10);
        $res = $c->upsert($key, ['foo' => 42], $options);
        $this->assertNotNull($res->cas());

        $options = new \Couchbase\GetOptions();
        $options->withExpiry(true);
        $res = $c->get($key, $options);
        $expiry = $res->expiryTime();
        $this->assertInstanceOf(DateTimeInterface::class, $expiry);
        $diff = $expiry->diff($now);
        $this->assertGreaterThan(0, $diff->s);
        $this->assertLessThanOrEqual(10, $diff->s);

        $options = new \Couchbase\LookupInOptions();
        $options->withExpiry(true);
        $res = $c->lookupIn($key, [new \Couchbase\LookupGetSpec("foo")], $options);
        $expiry = $res->expiryTime();
        $this->assertInstanceOf(DateTimeInterface::class, $expiry);
        $diff = $expiry->diff($now);
        $this->assertGreaterThan(0, $diff->s);
        $this->assertLessThanOrEqual(10, $diff->s);
    }

    function testExpirationForStoreOperations() {
        if ($this->usingMock()) {
            $this->markTestSkipped('Subdocument request to fetch time is not supported by CouchbaseMock.jar');
        }
        $c = $this->defaultCollection();
        $key = $this->makeKey('documentWithExpiry');

        $future = new DateTimeImmutable("2035-01-01");

        $options = new \Couchbase\UpsertOptions();
        $options->expiry($future);
        $res = $c->upsert($key, ['foo' => 42], $options);
        $this->assertNotNull($res->cas());

        $options = new \Couchbase\GetOptions();
        $options->withExpiry(true);
        $res = $c->get($key, $options);
        $this->assertEquals($future, $res->expiryTime());
    }
}
