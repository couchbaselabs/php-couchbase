<?php declare(strict_types=1);

require_once('CouchbaseTestCase.php');

class ViewQueryTest extends CouchbaseTestCase {
    public function setUp(): void {
        parent::setUp();
        $options = new \Couchbase\ClusterOptions();
        $options->credentials($this->testUser, $this->testPassword);
        $this->cluster = new \Couchbase\Cluster($this->testDsn, $options);
        $this->bucket = $this->cluster->bucket($this->testBucket);
        $this->collection = $this->bucket->defaultCollection();
        $this->manager = $this->bucket->viewIndexes();
        $this->setTimeouts($this->bucket);
    }

    function testConsistency() {
        if ($this->usingMock()) {
            $this->markTestSkipped('View consistency is not supported by the CouchbaseMock');
        }
        $ddocName = $this->makeKey('testConsistency');
        $view = new \Couchbase\View();
        $view->setName('test');
        $view->setMap("function(doc, meta) { if (meta.id.startsWith(\"{$ddocName}\")) emit(meta.id); }");
        $view->setReduce('_count');
        $ddoc = new \Couchbase\DesignDocument();
        $ddoc->setName("_design/" . $ddocName);
        $ddoc->setViews([$view->name() => $view]);
        $this->manager->upsertDesignDocument($ddoc);
        sleep(1); // give design document a second to settle

        $key = $this->makeKey($ddocName);
        $this->collection->upsert($key, ['foo' => 42]);

        $res = $this->bucket->viewQuery($ddocName, 'test');
        $this->assertEmpty($res->rows());

        $options = new \Couchbase\ViewOptions();
        $options->scanConsistency(\Couchbase\ViewScanConsistency::REQUEST_PLUS);
        $res = $this->bucket->viewQuery($ddocName, 'test', $options);
        $this->assertCount(1, $res->rows());
        $this->assertEquals($key, $res->rows()[0]->id());

        $this->manager->dropDesignDocument($ddocName);
    }

    function testGrouping() {
        $ddocName = $this->makeKey('ViewQueryTest');
        $view = new \Couchbase\View();
        $view->setName('test');
        $view->setMap("function(doc, meta) { if (doc && doc.ddoc == \"{$ddocName}\") emit([doc.country, doc.city]); }");
        $view->setReduce('_count');
        $ddoc = new \Couchbase\DesignDocument();
        $ddoc->setName("_design/" . $ddocName);
        $ddoc->setViews([$view->name() => $view]);

        $this->manager->upsertDesignDocument($ddoc);
        sleep(1); // give design document a second to settle

        $this->collection->upsert($this->makeKey($ddocName), ['ddoc' => $ddocName, 'country' => 'USA', 'city' => 'New York', 'name' => 'John Doe']);
        $this->collection->upsert($this->makeKey($ddocName), ['ddoc' => $ddocName, 'country' => 'USA', 'city' => 'New York', 'name' => 'Jane Doe']);
        $this->collection->upsert($this->makeKey($ddocName), ['ddoc' => $ddocName, 'country' => 'USA', 'city' => 'Miami', 'name' => 'Bill Brown']);
        $this->collection->upsert($this->makeKey($ddocName), ['ddoc' => $ddocName, 'country' => 'France', 'city' => 'Paris', 'name' => 'Jean Bon']);

        $options = new \Couchbase\ViewOptions();
        $options->scanConsistency(\Couchbase\ViewScanConsistency::REQUEST_PLUS);
        $res = $this->bucket->viewQuery($ddocName, 'test', $options);
        $this->assertCount(1, $res->rows());
        $this->assertEquals(4, $res->rows()[0]->value());

        $options = new \Couchbase\ViewOptions();
        $options->scanConsistency(\Couchbase\ViewScanConsistency::REQUEST_PLUS);
        $options->groupLevel(1);
        $res = $this->bucket->viewQuery($ddocName, 'test', $options);
        $this->assertCount(2, $res->rows());
        $this->assertEquals(["France"], $res->rows()[0]->key());
        $this->assertEquals(1, $res->rows()[0]->value());
        $this->assertEquals(["USA"], $res->rows()[1]->key());
        $this->assertEquals(3, $res->rows()[1]->value());

        $options = new \Couchbase\ViewOptions();
        $options->scanConsistency(\Couchbase\ViewScanConsistency::REQUEST_PLUS);
        $options->group(true);
        $res = $this->bucket->viewQuery($ddocName, 'test', $options);
        $this->assertCount(3, $res->rows());
        $this->assertEquals(["France", "Paris"], $res->rows()[0]->key());
        $this->assertEquals(1, $res->rows()[0]->value());
        $this->assertEquals(["USA", "Miami"], $res->rows()[1]->key());
        $this->assertEquals(1, $res->rows()[1]->value());
        $this->assertEquals(["USA", "New York"], $res->rows()[2]->key());
        $this->assertEquals(2, $res->rows()[2]->value());

        $options = new \Couchbase\ViewOptions();
        $options->scanConsistency(\Couchbase\ViewScanConsistency::REQUEST_PLUS);
        $options->group(true)->reduce(true)->keys(array_values([['USA', 'New York']]));
        $res = $this->bucket->viewQuery($ddocName, 'test', $options);
        $this->assertCount(1, $res->rows());
        $this->assertEquals(["USA", "New York"], $res->rows()[0]->key());
        $this->assertEquals(2, $res->rows()[0]->value());

        $this->manager->dropDesignDocument($ddocName);
    }
}
