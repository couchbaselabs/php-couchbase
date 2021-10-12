<?php declare(strict_types=1);
require_once('CouchbaseTestCase.php');

use \Couchbase\Cluster;
use \Couchbase\ClusterOptions;
use \Couchbase\GetOptions;
use \Couchbase\UpsertOptions;
use \Couchbase\ReplaceOptions;
use \Couchbase\RemoveOptions;
use \Couchbase\MutateInOptions;

class BucketTest extends CouchbaseTestCase {
    /**
     * Test that connections with invalid details fail.
     */
    function testBadPass() {
        $options = new ClusterOptions();
        $options->credentials($this->testUser, 'bad_pass');
        $this->wrapException(function() use($options) {
            new Cluster($this->testDsn, $options);
        }, '\Couchbase\AuthenticationException', COUCHBASE_ERR_AUTHENTICATION_FAILURE);
    }

    /**
     * Test that connections with invalid details fail.
     */
    function testBadBucket() {
        $options = new ClusterOptions();
        $options->credentials($this->testUser, $this->testPassword);
        $h = new Cluster($this->testDsn, $options);

        $this->wrapException(function() use($h) {
            $h->bucket('bad_bucket');
        }, '\Couchbase\BucketMissingException');
    }

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
     * Test basic upsert
     *
     * @depends testConnect
     */
    function testBasicUpsert($c) {
        $key = $this->makeKey('basicUpsert');
        $res = $c->upsert($key, ['name' => 'bob']);
        $this->assertNotNull($res->cas());
        return $key;
    }

    /**
     * Test basic get
     *
     * @depends testConnect
     * @depends testBasicUpsert
     */
    function testBasicGet($c, $key) {
        $res = $c->get($key);

        $this->assertNotNull($res->cas());
        $this->assertEquals($res->content(), ['name' => 'bob']);
        return $key;
    }

    /**
     * Verifies that library-generated CAS values work as expected
     *
     * @depends testConnect
     */
    function testGoodCas($c) {
        $key = $this->makeKey('goodCas');

        $res = $c->upsert($key, ['name' => 'bob']);
        $this->assertNotNull($res->cas());
        $cas1 = $res->cas();

        $options = new ReplaceOptions();
        $options->cas($cas1);
        $res = $c->replace($key, ['name' => 'john'], $options);
        $this->assertNotNull($res->cas());
        $cas2 = $res->cas();
        $this->assertNotEquals($cas1, $cas2);

        $res = $c->get($key);
        $this->assertEquals($cas2, $res->cas());
        $this->assertEquals($res->content(), ['name' => 'john']);
    }

    function testBadCas() {
        // strings are not CAS
        $options = new RemoveOptions();
        $this->wrapException(function() use($options) {
            $options->cas("0xdeadbeef");
        }, '\Couchbase\BadInputException');

        // Application should not attempt to generate CAS literals
        $options = new MutateInOptions();
        $this->wrapException(function() use($options) {
            $options->cas("776t3g==");
        }, '\Couchbase\BadInputException');
    }

    /**
     * Bad CAS for unlock
     *
     * @depends testConnect
     */
    function testBadCasWithUnlock($c) {
        $key = $this->makeKey('locks');

        $res = $c->upsert($key, 'jog');
        $this->assertNotNull($res->cas());

        // lock for 10 seconds
        $res = $c->getAndLock($key, 10);
        $this->assertNotNull($res->content());
        $this->assertNotNull($res->cas());
        $lockedCas = $res->cas();
        $badCas = "776t3g==";
        $this->assertNotEquals($badCas, $lockedCas);

        $this->wrapException(function() use($c, $key, $badCas) {
            $c->unlock($key, $badCas);
        }, '\Couchbase\BadInputException');
    }

    /**
     * Test reaction on empty value
     *
     * @depends testConnect
     */
    function testReadingEmptyString($c) {
        $key = $this->makeKey('emptyString');

        $passThruDecoder = function($bytes, $flags, $datatype) { return $bytes; };
        $passThruEncoder = function($value) { return [$value, 0x00, 0x00]; };

        $res = $c->upsert($key, "");
        $this->assertNotNull($res->cas());
        $cas = $res->cas();

        $res = $c->get($key);
        $this->assertEquals($cas, $res->cas());
        $this->assertEquals($res->content(), "");

        $options = new GetOptions();
        $options->decoder($passThruDecoder);
        $res = $c->get($key, $options);
        $this->assertEquals($cas, $res->cas());
        $this->assertEquals($res->content(), "");

        $options = new UpsertOptions();
        $options->encoder($passThruEncoder);
        $res = $c->upsert($key, "", $options);
        $this->assertNotNull($res->cas());
        $cas = $res->cas();

        $res = $c->get($key);
        $this->assertEquals($cas, $res->cas());
        $this->assertEquals($res->content(), "");

        $options = new GetOptions();
        $options->decoder($passThruDecoder);
        $res = $c->get($key, $options);
        $this->assertEquals($cas, $res->cas());
        $this->assertEquals($res->content(), "");

        $res = $c->upsert($key, null);
        $this->assertNotNull($res->cas());
        $cas = $res->cas();

        $res = $c->get($key);
        $this->assertEquals($cas, $res->cas());
        $this->assertEquals($res->content(), null);

        $options = new GetOptions();
        $options->decoder($passThruDecoder);
        $res = $c->get($key, $options);
        $this->assertEquals($cas, $res->cas());
        $this->assertEquals($res->content(), "null");
    }

    /**
     * Test basic remove
     *
     * @depends testConnect
     * @depends testBasicGet
     */
    function testBasicRemove($c, $key) {
        $res = $c->remove($key);

        $this->assertNotNull($res->cas());
        $this->wrapException(function() use($c, $key) {
            $c->get($key);
        }, '\Couchbase\KeyNotFoundException', COUCHBASE_ERR_DOCUMENT_NOT_FOUND);
    }

    /**
     * Test basic counter operations w/ an initial value
     *
     * @depends testConnect
     */
    function testCounterInitial($c) {
        $key = $this->makeKey('counterInitial');

        $options = new \Couchbase\IncrementOptions();
        $options->initial(1);
        $res = $c->binary()->increment($key, $options);
        $this->assertNotNull($res->cas());
        $this->assertEquals(1, $res->content());

        $res = $c->binary()->increment($key);
        $this->assertNotNull($res->cas());
        $this->assertEquals(2, $res->content());

        $res = $c->binary()->decrement($key);
        $this->assertNotNull($res->cas());
        $this->assertEquals(1, $res->content());
    }

    /**
     * @test
     * Test counter operations on missing keys
     *
     * @depends testConnect
     */
    function testCounterBadKey($c) {
        $key = $this->makeKey('counterBadKey');

        $this->wrapException(function() use($c, $key) {
            $c->binary()->increment($key);
        }, '\Couchbase\KeyNotFoundException', COUCHBASE_ERR_DOCUMENT_NOT_FOUND);

        $this->wrapException(function() use($c, $key) {
            $c->binary()->decrement($key);
        }, '\Couchbase\KeyNotFoundException', COUCHBASE_ERR_DOCUMENT_NOT_FOUND);

        $options = (new \Couchbase\DecrementOptions())->initial(42);
        $res = $c->binary()->decrement($key, $options);
        $this->assertNotNull($res->cas());
        $this->assertEquals(42, $res->content());
    }

    /**
     * Test expiry operations on keys
     *
     * @depends testConnect
     */
    function testExpiry($c) {
        $key = $this->makeKey('expiry');

        $options = (new \Couchbase\UpsertOptions())->expiry(1);
        $c->upsert($key, 'dog', $options);

        sleep(2);

        $this->wrapException(function() use($c, $key) {
            $c->get($key);
        }, '\Couchbase\KeyNotFoundException', COUCHBASE_ERR_DOCUMENT_NOT_FOUND);
    }

    /**
     * Test CAS works
     *
     * @depends testConnect
     */
    function testCas($c) {
        $key = $this->makeKey('cas');

        $res = $c->upsert($key, 'dog');
        $this->assertNotNull($res->cas());
        $old_cas = $res->cas();

        $res = $c->upsert($key, 'cat');
        $this->assertNotNull($res->cas());
        $this->assertNotEquals($old_cas, $res->cas());

        $this->wrapException(function() use($c, $key, $old_cas) {
            $options = (new \Couchbase\ReplaceOptions())->cas($old_cas);
            $c->replace($key, 'ferret', $options);
        }, '\Couchbase\CasMismatchException', COUCHBASE_ERR_CAS_MISMATCH);
    }

    /**
     * Test Locks work
     *
     * @depends testConnect
     */
    function testLocks($c) {
        $key = $this->makeKey('locks');

        $res = $c->upsert($key, 'jog');
        $this->assertNotNull($res->cas());

        // lock for 10 seconds
        $res = $c->getAndLock($key, 10);
        $this->assertNotNull($res->content());
        $this->assertNotNull($res->cas());
        $lockedCas = $res->cas();

        $this->wrapException(function() use($c, $key) {
            // key is not accessible for locking
            $c->getAndLock($key, 1);
        }, '\Couchbase\TempFailException', COUCHBASE_TMPFAIL);

        $res = $c->unlock($key, $lockedCas);

        // accessible for locking again
        $res = $c->getAndLock($key, 1);
        $this->assertNotNull($res->content());
        $this->assertNotNull($res->cas());
    }

    /**
     * Test big upserts
     *
     * @depends testConnect
     */
    function testBigUpsert($c) {
        $key = $this->makeKey('bigUpsert');

        // $v = str_repeat("*", 0x1000000);
        $v = str_repeat("*", 0x100000);
        $res = $c->upsert($key, $v);
        $this->assertNotNull($res->cas());

        $c->remove($key);

        return $key;
    }

    /**
     * @test
     * Test upsert with no key specified
     *
     * @depends testConnect
     */
    function testNoKeyUpsert($c) {
        $this->wrapException(function() use($c) {
            $c->upsert('', 'joe');
        }, '\Couchbase\BadInputException', COUCHBASE_ERR_EMPTY_KEY);
    }

    /**
     * Test all option values to make sure they save/load
     * We open a new bucket for this test to make sure our settings
     * changes do not affect later tests. Console log level option used
     * to generate unique (for these test suites) connection string,
     * so that the lcb_t won't be reused from the pool
     */
    function testOptionVals() {
        $options = new ClusterOptions();
        $options->credentials($this->testUser, $this->testPassword);
        $h = new Cluster($this->testDsn . "?console_log_level=42", $options);
        $b = $h->bucket($this->testBucket);

        $checkVal = 50243;

        $b->operationTimeout = $checkVal;
        $b->viewTimeout = $checkVal;
        $b->durabilityInterval = $checkVal;
        $b->durabilityTimeout = $checkVal;
        $b->httpTimeout = $checkVal;
        $b->configTimeout = $checkVal;
        $b->configDelay = $checkVal;
        $b->configNodeTimeout = $checkVal;
        $b->htconfigIdleTimeout = $checkVal;
        $b->configPollInterval = $checkVal;

        $this->assertEquals($b->operationTimeout, $checkVal);
        $this->assertEquals($b->viewTimeout, $checkVal);
        $this->assertEquals($b->durabilityInterval, $checkVal);
        $this->assertEquals($b->durabilityTimeout, $checkVal);
        $this->assertEquals($b->httpTimeout, $checkVal);
        $this->assertEquals($b->configTimeout, $checkVal);
        $this->assertEquals($b->configDelay, $checkVal);
        $this->assertEquals($b->configNodeTimeout, $checkVal);
        $this->assertEquals($b->htconfigIdleTimeout, $checkVal);
        $this->assertEquals($b->configPollInterval, $checkVal);
    }

    /**
     * @depends testConnect
     */
    function testLookupInFulldoc($c) {
        $key = $this->makeKey('lookup_in_fulldoc');
        $c->upsert($key, ['path1' => 42, 'path2' => 'foo']);

        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec(''),
            new \Couchbase\LookupGetSpec('path2'),
        ]);
        $this->assertNotNull($result->cas());
        $this->assertEquals(['path1' => 42, 'path2' => 'foo'], $result->content(0));
        $this->assertEquals('foo', $result->content(1));
    }

    /**
     * @depends testConnect
     */
    function testLookupIn($c) {
        $key = $this->makeKey('lookup_in');
        $c->upsert($key, ['path1' => 'value1']);

        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('path1')
        ]);
        $this->assertEquals('value1', $result->content(0));
        $this->assertNotEmpty($result->cas());

        # Try when path is not found
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('path2')
        ]);
        $this->assertNotNull($result->cas());
        $this->assertNull($result->content(0));
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_NOT_FOUND, $result->status(0));

        # Try when there is a mismatch
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('path1[0]')
        ]);
        $this->assertNotNull($result->cas());
        $this->assertNull($result->content(0));
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_MISMATCH, $result->status(0));

        # Try existence
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupExistsSpec('path1')
        ]);
        $this->assertNotNull($result->cas());
        $this->assertTrue($result->exists(0));

        # Not found
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupExistsSpec('p')
        ]);
        $this->assertNotNull($result->cas());
        $this->assertFalse($result->exists(0));

        # Insert a non-JSON document
        $key = $this->makeKey('lookup_in_nonjson');
        $c->upsert($key, 'value');

        $this->wrapException(function() use($c, $key) {
            $result = $c->lookupIn($key, [
                new \Couchbase\LookupExistsSpec('path')
            ]);
        }, '\Couchbase\SubdocumentException', COUCHBASE_ERR_SUBDOC_DOCUMENT_NOT_JSON);

        # Try on non-existing document. Should fail
        $key = $this->makeKey('lookup_in_with_missing_key');
        $this->wrapException(function() use($c, $key) {
            $c->lookupIn($key, [
                new \Couchbase\LookupExistsSpec('path')
            ]);
        }, '\Couchbase\KeyNotFoundException');
    }

    /**
     * @depends testConnect
     */
    function testGetCount($c) {
        $key = $this->makeKey('get_count');
        $c->upsert($key, ['list' => [1, 2, 42], 'object' => ['foo' => 42]]);

        $result = $c->lookupIn($key, [
            new \Couchbase\LookupCountSpec('list'),
            new \Couchbase\LookupCountSpec('object')
        ]);
        $this->assertNotNull($result->cas());
        $this->assertEquals(3, $result->content(0));
        $this->assertEquals(1, $result->content(1));
    }

    /**
     * @depends testConnect
     */
    function testLookupInWithEmptyPath($c) {
        $key = $this->makeKey('lookup_in_with_empty_path');
        $c->upsert($key, array('path1' => 'value1'));

        $this->expectException(\Couchbase\BadInputException::class);
        $c->lookupIn($key, [
            new \Couchbase\LookupExistsSpec(''),
        ]);
    }

    /**
     * @depends testConnect
     */
    function testMutateInWithExpiry($c) {
        $key = $this->makeKey('mutate_in_with_expiry');
        $key = 'mutate_in_with_expiry';
        $c->upsert($key, new stdClass());

        $options = (new \Couchbase\MutateInOptions())->expiry(1);
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('foo', 'bar')
        ], $options);
        $this->assertEquals(COUCHBASE_SUCCESS, $result->status(0));

        sleep(2);

        $this->wrapException(function() use($c, $key) {
            $c->get($key);
        }, '\Couchbase\KeyNotFoundException', COUCHBASE_ERR_DOCUMENT_NOT_FOUND);
    }

    /**
     * @depends testConnect
     */
    function testMutateInFulldoc($c) {
        $key = $this->makeKey('mutate_in_fulldoc');

        $options = (new \Couchbase\MutateInOptions())->storeSemantics(\Couchbase\StoreSemantics::UPSERT);
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('created_at', time(), true, true),
            new \Couchbase\MutateReplaceSpec('', ["new" => "yes"])
        ], $options);
        $this->assertNotNull($result->cas());

        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('new')
        ]);
        $this->assertEquals("yes", $result->content(0));

        $this->wrapException(function() use($c, $key) {
            $options = (new \Couchbase\MutateInOptions())->storeSemantics(\Couchbase\StoreSemantics::INSERT);
            $result = $c->mutateIn($key, [
                new \Couchbase\MutateUpsertSpec('created_at', time(), true, true),
                new \Couchbase\MutateReplaceSpec('', ["duplicate" => "yes"])
            ], $options);
        }, '\Couchbase\KeyExistsException');

        $options = (new \Couchbase\MutateInOptions())->storeSemantics(\Couchbase\StoreSemantics::REPLACE);
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('created_at', time(), true, true),
            new \Couchbase\MutateReplaceSpec('', ["updated" => "yes"])
        ], $options);
        $this->assertNotNull($result->cas());

        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('updated')
        ]);
        $this->assertEquals("yes", $result->content(0));
    }

    /**
     * @depends testConnect
     */
    function testMutateIn($c) {
        $key = $this->makeKey('mutate_in');
        $c->upsert($key, new stdClass());

        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('newDict', ['hello']),
        ]);
        $this->assertNotNull($result->cas());
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('newDict'),
        ]);
        $this->assertNotNull($result->cas());
        $this->assertEquals(['hello'], $result->content(0));

        # Does not create deep path without create_parents
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('path.with.missing.parents', 'value'),
        ]);
        $this->assertNotNull($result->cas());
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_NOT_FOUND, $result->status(0));

        # Creates deep path without create_parents
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('path.with.missing.parents', 'value', false, true),
        ]);
        $this->assertNotNull($result->cas());
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('path.with.missing.parents'),
        ]);
        $this->assertNotNull($result->cas());
        $this->assertEquals('value', $result->content(0));
        $cas = $result->cas();

        $this->wrapException(function() use($c, $key) {
            $options = (new \Couchbase\MutateInOptions())->cas(base64_encode("deadbeef"));
            $result = $c->mutateIn($key, [
                new \Couchbase\MutateUpsertSpec('newDict', 'withWrongCAS'),
            ], $options);
        }, '\Couchbase\CasMismatchException');

        # once again with correct CAS
        $options = (new \Couchbase\MutateInOptions())->cas($cas);
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('newDict', 'withCorrectCAS'),
        ], $options);
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('newDict'),
        ]);
        $this->assertEquals('withCorrectCAS', $result->content(0));

        # insert into existing path should fail
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateInsertSpec('newDict', ['foo' => 42]),
        ]);
        $this->assertNotNull($result->cas());
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_EXISTS, $result->status(0));

        # insert into new path should succeed
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateInsertSpec('anotherDict', ['foo' => 42]),
        ]);
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('anotherDict'),
        ]);
        $this->assertEquals(['foo' => 42], $result->content(0));

        # replace of existing path should not fail
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateReplaceSpec('newDict', [42 => 'foo']),
        ]);
        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('newDict'),
        ]);
        $this->assertEquals([42 => 'foo'], $result->content(0));

        # replace of missing path should not fail
        $result = $c->mutateIn($key, [
            new \Couchbase\MutateReplaceSpec('missingDict', [42 => 'foo']),
        ]);
        $this->assertNotNull($result->cas());
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_NOT_FOUND, $result->status(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateUpsertSpec('empty', '')]);
        $result = $c->lookupIn($key, [new \Couchbase\LookupGetSpec('empty')]);
        $this->assertEquals('', $result->content(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateUpsertSpec('null', null)]);
        $result = $c->lookupIn($key, [new \Couchbase\LookupGetSpec('null')]);
        $this->assertEquals(null, $result->content(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateUpsertSpec('array', [1, 2, 3])]);
        $result = $c->lookupIn($key, [new \Couchbase\LookupGetSpec('array')]);
        $this->assertEquals([1, 2, 3], $result->content(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateUpsertSpec('array.newKey', 'newVal')]);
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_MISMATCH, $result->status(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateUpsertSpec('array[0]', 'newVal')]);
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_INVALID, $result->status(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateUpsertSpec('array[1].bleh', 'newVal')]);
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_MISMATCH, $result->status(0));
    }

    /**
     * @depends testConnect
     */
    function testSubdocUpsertWithEmptyPath($c) {
        $key = $this->makeKey('upsert_in_with_empty_path');
        $c->upsert($key, ['path1' => 'value1']);

        $this->expectException(\Couchbase\BadInputException::class);
        $result = $c->mutateIn($key, [new \Couchbase\MutateUpsertSpec('', 'value')]);
    }

    /**
     * @depends testConnect
     */
    function testSubdocReplaceWithEmptyPath($c) {
        $key = $this->makeKey('replace_in_with_empty_path');
        $c->upsert($key, ['path1' => 'value1']);

        $c->mutateIn($key, [new \Couchbase\MutateReplaceSpec('', ['path2' => 'value2'])]);
        $result = $c->get($key);
        $this->assertEquals($result->content(), ['path2' => 'value2']);
    }

    /**
     * @depends testConnect
     */
    function testSubdocRemoveWithEmptyPath($c) {
        if ($this->usingMock()) {
            $this->markTestSkipped('CouchbaseMock does not support remove with empty path');
        }
        $key = $this->makeKey('remove_in_with_empty_path');
        $c->upsert($key, ['path1' => 'value1']);

        $c->mutateIn($key, [new \Couchbase\MutateRemoveSpec('')]);
        $this->expectException(\Couchbase\DocumentNotFoundException::class);
        $c->get($key);
    }

    /**
     * @depends testConnect
     */
    function testCounterIn($c) {
        $key = $this->makeKey('mutate_in');
        $c->upsert($key, new stdClass());

        $result = $c->mutateIn($key, [new \Couchbase\MutateCounterSpec('counter', 100)]);
        $this->assertNotEmpty($result->cas());
        $this->assertEquals(100, $result->content(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateUpsertSpec('not_a_counter', 'foobar')]);
        $this->assertNotEmpty($result->cas());

        $result = $c->mutateIn($key, [new \Couchbase\MutateCounterSpec('not_a_counter', 100)]);
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_MISMATCH, $result->status(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateCounterSpec('path.to.new.counter', 100)]);
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_NOT_FOUND, $result->status(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateCounterSpec('path.to.new.counter', 100, false, true)]);
        $this->assertNotEmpty($result->cas());
        $this->assertEquals(100, $result->content(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateCounterSpec('counter', -25)]);
        $this->assertNotEmpty($result->cas());
        $this->assertEquals(75, $result->content(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateCounterSpec('counter', 0)]);
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_DELTA_INVALID, $result->status(0));
    }

    /**
     * @depends testConnect
     */
    function testMultiLookupIn($c) {
        $key = $this->makeKey('multi_lookup_in');
        $c->upsert($key, [
            'field1' => 'value1',
            'field2' => 'value2',
            'array' =>  [1, 2, 3],
            'boolean' => false,
        ]);

        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('field1'),
            new \Couchbase\LookupExistsSpec('field2'),
            new \Couchbase\LookupExistsSpec('field3'),
        ]);
        $this->assertEquals('value1', $result->content(0));
        $this->assertEquals(null, $result->content(1));
        $this->assertTrue($result->exists(1));
        $this->assertFalse($result->exists(2));
    }

    /**
     * @depends testConnect
     */
    function testMultiMutateIn($c) {
        $key = $this->makeKey('multi_mutate_in');
        $c->upsert($key, array(
            'field1' => 'value1',
            'field2' => 'value2',
            'array' =>  array(1, 2, 3),
        ));

        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('field1', ['foo' => 'bar']),
            new \Couchbase\MutateRemoveSpec('array'),
            new \Couchbase\MutateReplaceSpec('missing', 'hello world'),
        ]);
        $this->assertEquals(COUCHBASE_SUCCESS, $result->status(0));
        $this->assertEquals(COUCHBASE_SUCCESS, $result->status(1));
        $this->assertEquals(COUCHBASE_ERR_SUBDOC_PATH_NOT_FOUND, $result->status(2));

        $result = $c->lookupIn($key, [
            new \Couchbase\LookupGetSpec('field1'),
            new \Couchbase\LookupExistsSpec('array'),
        ]);
        $this->assertEquals('value1', $result->content(0));
        $this->assertTrue($result->exists(1));
    }

    /**
     * @depends testConnect
     */
    function testMultiValue($c) {
        $key = $this->makeKey('multi_value');
        $c->upsert($key, ['array' => []]);

        $result = $c->mutateIn($key, [new \Couchbase\MutateArrayAppendSpec('array', [true])]);
        $result = $c->lookupIn($key, [new \Couchbase\LookupGetSpec('array')]);
        $this->assertEquals([true], $result->content(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateArrayAppendSpec('array', [1, 2, 3])]);
        $result = $c->lookupIn($key, [new \Couchbase\LookupGetSpec('array')]);
        $this->assertEquals([true, 1, 2, 3], $result->content(0));

        $result = $c->mutateIn($key, [new \Couchbase\MutateArrayPrependSpec('array', [[42]])]);
        $result = $c->lookupIn($key, [new \Couchbase\LookupGetSpec('array')]);
        $this->assertEquals([[42], true, 1, 2, 3], $result->content(0));
    }

    /**
     * @depends testConnect
     */
    function testSubdocAttributes($c) {
        $key = $this->makeKey('subdoc_attributes');
        $c->upsert($key, ['foo' => 'bar']);

        $result = $c->mutateIn($key, [
            new \Couchbase\MutateUpsertSpec('app.created_by', ['name' => 'John Doe', 'role' => 'DB administrator'], true, true),
        ]);
        $result = $c->lookupIn($key, [new \Couchbase\LookupGetSpec('app.created_by', true)]);
        $this->assertEquals(['name' => 'John Doe', 'role' => 'DB administrator'], $result->content(0));
    }

//  /**
//   * @test
//   * Test recursive transcoder functions
//   */
//  function testRecursiveTranscode() {
//      global $recursive_transcoder_bucket;
//      global $recursive_transcoder_key2;
//      global $recursive_transcoder_key3;

//      $h = new \Couchbase\Cluster($this->testDsn);
//      $h->authenticate($this->testAuthenticator);
//      $c = $h->bucket($this->testBucket)->defaultCollection();
//      $this->setTimeouts($c);

//      $key1 = $this->makeKey('basicUpsertKey1');
//      $key2 = $this->makeKey('basicUpsertKey2');
//      $key3 = $this->makeKey('basicUpsertKey3');

//      // Set up a transcoder that upserts key2 when it sees key1
//      $recursive_transcoder_bucket = $c;
//      $recursive_transcoder_key2 = $key2;
//      $recursive_transcoder_key3 = $key3;
//      $c->setTranscoder(
//          'recursive_transcoder_encoder',  // defined at bottom of file
//          'recursive_transcoder_decoder'); // defined at bottom of file

//      // Upsert key1, transcoder should set key2
//      $res = $c->upsert($key1, 'key1');
//      $this->assertValidMetaDoc($res, 'cas');

//      // Check key1 was upserted
//      $res = $c->get($key1);
//      $this->assertValidMetaDoc($res, 'cas');
//      $this->assertEquals($res->value, 'key1');

//      // Check key2 was upserted, trasncoder should set key3
//      $res = $c->get($key2);
//      $this->assertValidMetaDoc($res, 'cas');
//      $this->assertEquals($res->value, 'key2');

//      // Check key3 was upserted
//      $res = $c->get($key3);
//      $this->assertValidMetaDoc($res, 'cas');
//      $this->assertEquals($res->value, 'key3');
//  }
}

// function recursive_transcoder_encoder($value) {
//     global $recursive_transcoder_bucket;
//     global $recursive_transcoder_key2;
//     if ($value == 'key1') {
//         $recursive_transcoder_bucket->upsert(
//             $recursive_transcoder_key2, 'key2');
//     }
//     return couchbase_default_encoder($value);
// }
//
// function recursive_transcoder_decoder($bytes, $flags, $datatype) {
//     global $recursive_transcoder_bucket;
//     global $recursive_transcoder_key3;
//     $value = couchbase_default_decoder($bytes, $flags, $datatype);
//     if ($value == 'key2') {
//         $recursive_transcoder_bucket->upsert(
//             $recursive_transcoder_key3, 'key3');
//     }
//     return $value;
// }
