<?php declare(strict_types=1);

require_once('CouchbaseTestCase.php');

class N1qlQueryTest extends CouchbaseTestCase {
    private $cluster;

    public function setUp(): void {
        parent::setUp();
        $options = new \Couchbase\ClusterOptions();
        $options->credentials($this->testUser, $this->testPassword);
        $this->cluster = new \Couchbase\Cluster($this->testDsn, $options);
    }

    function testAlreadyHaveCreatedIndex() {
        if ($this->usingMock()) {
            $this->markTestSkipped('N1QL indexes are not supported by the CouchbaseMock');
        }
        $indexManager = $this->cluster->queryIndexes();
        $indexManager->dropPrimaryIndex('default', true);
        $indexManager->createPrimaryIndex('default');
    }

    function testResponseProperties() {
        if ($this->usingMock()) {
            $this->markTestSkipped('N1QL queries are not supported by the CouchbaseMock');
        }
        $key = $this->makeKey("n1qlResponseProperties");
        $collection = $this->cluster->bucket($this->testBucket)->defaultCollection();
        $collection->upsert($key, ["bar" => 42]);
        $options = (new \Couchbase\QueryOptions())->scanConsistency(\Couchbase\QueryScanConsistency::REQUEST_PLUS);
        $res = $this->cluster->query("SELECT * FROM `{$this->testBucket}` USE KEYS \"$key\"", $options);
        $meta = $res->metaData();
        $this->assertNotEmpty($meta);
        $this->assertEquals("success", $meta->status());
        $this->assertNotNull($meta->requestId());
        $this->assertNotNull($meta->metrics());
        $this->assertNotNull($meta->signature());
        $rows = $res->rows();
        $this->assertNotEmpty($rows);
        $this->assertEquals(42, $res->rows()[0][$this->testBucket]['bar']);
    }

    function testParameters() {
        if ($this->usingMock()) {
            $this->markTestSkipped('N1QL queries are not supported by the CouchbaseMock');
        }
        $key = $this->makeKey("n1qlParameters");
        $bucketName = $this->testBucket;
        $collection = $this->cluster->bucket($bucketName)->defaultCollection();
        $collection->upsert($key, ["bar" => 42]);

        $options = (new \Couchbase\QueryOptions())
                    ->scanConsistency(\Couchbase\QueryScanConsistency::REQUEST_PLUS)
                    ->positionalParameters([$key]);
        $res = $this->cluster->query("SELECT * FROM `$bucketName` USE KEYS \$1", $options);
        $this->assertNotEmpty($res->rows());
        $this->assertEquals(42, $res->rows()[0][$bucketName]['bar']);

        $options = (new \Couchbase\QueryOptions())
                    ->scanConsistency(\Couchbase\QueryScanConsistency::REQUEST_PLUS)
                    ->namedParameters(["key" => $key]);
        $res = $this->cluster->query("SELECT * FROM `$bucketName` USE KEYS \$key", $options);
        $this->assertNotEmpty($res->rows());
        $this->assertEquals(42, $res->rows()[0][$bucketName]['bar']);

        // it will use PHP interpolation, and actually breaks query
        $this->wrapException(function() use($bucketName, $key) {
            $options = (new \Couchbase\QueryOptions())
                        ->scanConsistency(\Couchbase\QueryScanConsistency::REQUEST_PLUS)
                        ->namedParameters(["key" => $key]);
            $this->cluster->query("SELECT * FROM `$bucketName` USE KEYS $key", $options);
        }, '\Couchbase\HttpException', 3000, '/Ambiguous reference to field/');
    }

    function testAtPlus() {
        if ($this->usingMock()) {
            $this->markTestSkipped('N1QL queries are not supported by the CouchbaseMock');
        }
        $bucketName = $this->testBucket;
        $collection = $this->cluster->bucket($bucketName)->defaultCollection();

        $key = $this->makeKey("atPlus");
        $random = rand(0, 1000000);
        $result = $collection->upsert($key, [
            "name" => ["Brass", "Doorknob"],
            "email" => "brass.doorknob@example.com",
            "random" => $random
        ]);
        // construct mutation state from the list of mutation results
        $mutationState = new \Couchbase\MutationState();
        $mutationState->add($result);

        $options = (new \Couchbase\QueryOptions())
                    ->consistentWith($mutationState)
                    ->positionalParameters(['Brass']);
        $result = $this->cluster->query("SELECT name, random, META($bucketName).id FROM `$bucketName` WHERE \$1 IN name", $options);
        $found = false;
        foreach ($result->rows() as $row) {
            if ($row['random'] == $random) {
                $found = true;
            }
        }
        $this->assertTrue($found, "The record \"$key\" is missing in the result set");
    }

    function testRowsShape() {
        if ($this->usingMock()) {
            $this->markTestSkipped('N1QL queries are not supported by the CouchbaseMock');
        }

        ini_set("couchbase.decoder.json_arrays", "0");
        $result = $this->cluster->query("SELECT 'Hello, PHP!' AS message");
        $this->assertNotEmpty($result->rows());
        $row = $result->rows()[0];
        $this->assertIsNotArray($row);
        $this->assertEquals("Hello, PHP!", $row->message);

        ini_set("couchbase.decoder.json_arrays", "1");
        $result = $this->cluster->query("SELECT 'Hello, PHP!' AS message");
        $this->assertNotEmpty($result->rows());
        $row = $result->rows()[0];
        $this->assertIsArray($row);
        $this->assertEquals("Hello, PHP!", $row["message"]);
    }
}
