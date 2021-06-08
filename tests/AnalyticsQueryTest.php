<?php declare(strict_types=1);

require_once('CouchbaseTestCase.php');

class AnalyticsQueryTest extends CouchbaseTestCase {
    private $cluster;

    public function setUp(): void {
        parent::setUp();
        $options = new \Couchbase\ClusterOptions();
        $options->credentials($this->testUser, $this->testPassword);
        $this->cluster = new \Couchbase\Cluster($this->testDsn, $options);
    }

    function testAlreadyHaveCreatedAnalyticsIndex() {
        if ($this->usingMock()) {
            $this->markTestSkipped('Analytics indexes are not supported by the CouchbaseMock');
        }
        $bucketName = $this->testBucket;
        try {
            $this->cluster->analyticsQuery("ALTER COLLECTION $bucketName._default._default ENABLE ANALYTICS");
        } catch (Exception $e) {}
    }

    function testScopeAnalyticsQuery() {
        if ($this->usingMock()) {
            $this->markTestSkipped('Analytics queries are not supported by the CouchbaseMock');
        }
        $key = $this->makeKey("analyticsScope");
        $bucketName = $this->testBucket;
        $bucket = $this->cluster->bucket($bucketName);
        $scope = $bucket->scope("_default");
        $collection = $bucket->defaultCollection();
        $collection->upsert($key, ["bar" => 42]);

        $options = (new \Couchbase\AnalyticsOptions())
                    ->scanConsistency("request_plus")
                    ->positionalParameters([$key]);
        $res = $scope->analyticsQuery("SELECT * FROM `_default` where meta().id = \$1", $options);
        $this->assertNotEmpty($res->rows());
        $this->assertEquals(42, $res->rows()[0]["_default"]['bar']);
    }
}
