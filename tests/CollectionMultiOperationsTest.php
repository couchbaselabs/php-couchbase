<?php declare(strict_types=1);
require_once('CouchbaseTestCase.php');

use \Couchbase\Cluster;
use \Couchbase\ClusterOptions;
use \Couchbase\GetOptions;
use \Couchbase\UpsertOptions;
use \Couchbase\RemoveOptions;

class CollectionMultiOperationsTest extends CouchbaseTestCase {
    /**
     * Test that a connection with accurate details works.
     */
    function testConnect() {
        $options = new ClusterOptions();
        $options->credentials($this->testUser, $this->testPassword);
        $h = new Cluster($this->testDsn, $options);
        $b = $h->bucket($this->testBucket);
        $this->assertNotNull($b);
        $this->setTimeouts($b);
        return $b->defaultCollection();
    }

    /**
     * @depends testConnect
     */
    function testGetMulti($c) {
        $ids = [
            $this->makeKey('id1'),
            $this->makeKey('id2'),
            $this->makeKey('id3')
        ];
        foreach ($ids as $id) {
            $c->upsert($id, ['val' => $id]);
        }

        $res = $c->getMulti($ids);

        $this->assertIsArray($res);
        $this->assertCount(3, $res);
        for ($i = 0; $i < 3; ++$i) {
            $this->assertNotNull($res[$i]->cas());
            $this->assertEquals($res[$i]->content(), ['val' => $ids[$i]]);
        }
    }

    /**
     * @depends testConnect
     */
    function testGetMultiWithInvalidKey($c) {
        $ids = [
            $this->makeKey('id1'),
            "",
            $this->makeKey('id3')
        ];


        $this->wrapException(function() use($c, $ids) {
            $c->getMulti($ids);
        }, '\Couchbase\BadInputException');
    }

    /**
     * @depends testConnect
     */
    function testGetMultiWithMissingKey($c) {
        $ids = [
            $this->makeKey('id1'),
            $this->makeKey('id2'),
        ];
        foreach ($ids as $id) {
            $c->upsert($id, ['val' => $id]);
        }

        $ids[] = $this->makeKey('id3');
        $res = $c->getMulti($ids);

        $this->assertIsArray($res);
        $this->assertCount(3, $res);
        for ($i = 0; $i < 2; ++$i) {
            $this->assertNotNull($res[$i]->cas());
            $this->assertEquals($res[$i]->content(), ['val' => $ids[$i]]);
        }
        $this->assertInstanceOf(Couchbase\DocumentNotFoundException::class, $res[2]->error());
        $this->assertNull($res[2]->cas());
        $this->assertEquals("", $res[2]->content());
    }

    /**
     * @depends testConnect
     */
    function testRemoveMulti($c) {
        $ids = [
            $this->makeKey('id1'),
            $this->makeKey('id2'),
            $this->makeKey('id3')
        ];
        foreach ($ids as $id) {
            $c->upsert($id, ['val' => $id]);
        }

        $res = $c->removeMulti($ids);

        $this->assertIsArray($res);
        $this->assertCount(3, $res);
        for ($i = 0; $i < 3; ++$i) {
            $this->assertNull($res[$i]->error());
            $this->assertNotNull($res[$i]->cas());
        }
    }

    /**
     * @depends testConnect
     */
    function testRemoveMultiWithCas($c) {
        $ids = [
            $this->makeKey('id1'),
            $this->makeKey('id2'),
            $this->makeKey('id3')
        ];
        $idsWithCas = [];
        foreach ($ids as $id) {
            $res = $c->upsert($id, ['val' => $id]);
            $idsWithCas[] = [$id, $res->cas()];
        }

        // nullify the CAS for second key
        $idsWithCas[1][1] = null;

        $res = $c->removeMulti($idsWithCas);

        $this->assertIsArray($res);
        $this->assertCount(3, $res);
        for ($i = 0; $i < 3; ++$i) {
            $this->assertNull($res[$i]->error());
            $this->assertNotNull($res[$i]->cas());
        }
    }

    /**
     * @depends testConnect
     */
    function testRemoveMultiWithStaleCas($c) {
        $ids = [
            $this->makeKey('id1'),
            $this->makeKey('id2'),
            $this->makeKey('id3')
        ];
        $idsWithCas = [];
        foreach ($ids as $id) {
            $res = $c->upsert($id, ['val' => $id]);
            $idsWithCas[] = [$id, $res->cas()];
        }
        // make CAS for third key stale
        $c->upsert($ids[2], ['val' => $ids[2]]);

        $res = $c->removeMulti($idsWithCas);

        $this->assertIsArray($res);
        $this->assertCount(3, $res);
        for ($i = 0; $i < 2; ++$i) {
            $this->assertNull($res[$i]->error());
            $this->assertNotNull($res[$i]->cas());
        }

        $this->assertInstanceOf(\Couchbase\CasMismatchException::class, $res[2]->error());
        $this->assertNull($res[2]->cas());
    }

    /**
     * @depends testConnect
     */
    function testUpsertMulti($c) {
        $idsWithValue = [];
        $ids = [];
        for ($i = 0; $i < 3; ++$i) {
            $id = $this->makeKey("id$i");
            $idsWithValue[] = [$id, ['val' => $id]];
            $ids[] = $id;
        }

        $res = $c->upsertMulti($idsWithValue);

        $this->assertIsArray($res);
        $this->assertCount(3, $res);
        for ($i = 0; $i < 3; ++$i) {
            $this->assertNull($res[$i]->error());
            $this->assertNotNull($res[$i]->cas());
        }

        $res = $c->getMulti($ids);

        $this->assertIsArray($res);
        $this->assertCount(3, $res);
        for ($i = 0; $i < 3; ++$i) {
            $this->assertNull($res[$i]->error());
            $this->assertNotNull($res[$i]->cas());
            $this->assertEquals($res[$i]->content(), ['val' => $ids[$i]]);
        }
    }
}
