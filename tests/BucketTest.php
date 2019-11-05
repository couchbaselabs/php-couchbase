<?php
require_once('CouchbaseTestCase.php');

class BucketTest extends CouchbaseTestCase {

    /**
     * Test that connections with invalid details fail.
     */
    function testBadPass() {
        $h = new \Couchbase\Cluster($this->testDsn);

        $this->wrapException(function() use($h) {
            if ($this->serverVersion() >= 5.0) {
                $auth = new \Couchbase\PasswordAuthenticator();
                $auth->username($this->testBucket)->password('bad_pass');
            } else {
                $auth = new \Couchbase\ClassicAuthenticator();
                $auth->bucket($this->testBucket, 'bad_pass');
            }
            $h->authenticate($auth);
            $h->openBucket('default');
        }, '\Couchbase\Exception', 2);
    }

    /**
     * Test that connections with invalid details fail.
     */
    function testBadBucket() {
        $h = new \Couchbase\Cluster($this->testDsn);
        $h->authenticate($this->testAuthenticator);

        $this->wrapException(function() use($h) {
            $h->openBucket('bad_bucket');
        }, '\Couchbase\Exception');
    }

    /**
     * Test that a connection with accurate details works.
     */
    function testConnect() {
        $h = new \Couchbase\Cluster($this->testDsn);
        $h->authenticate($this->testAuthenticator);
        $b = $h->openBucket($this->testBucket);
        $this->setTimeouts($b);
        return $b;
    }

    /**
     * Test basic upsert
     *
     * @depends testConnect
     */
    function testBasicUpsert($b) {
        $key = $this->makeKey('basicUpsert');

        $res = $b->upsert($key, 'bob');

        $this->assertValidMetaDoc($res, 'cas');

        return $key;
    }

    /**
     * Test basic get
     *
     * @depends testConnect
     * @depends testBasicUpsert
     */
    function testBasicGet($b, $key) {
        $res = $b->get($key);

        $this->assertValidMetaDoc($res, 'value', 'cas', 'flags');
        $this->assertEquals($res->value, 'bob');

        return $key;
    }

    /**
     * Test basic remove
     *
     * @depends testConnect
     * @depends testBasicGet
     */
    function testBasicRemove($b, $key) {
        $res = $b->remove($key);

        $this->assertValidMetaDoc($res, 'cas');

        // This should throw a not-found exception
        $this->wrapException(function() use($b, $key) {
            $b->get($key);
        }, '\Couchbase\Exception', COUCHBASE_KEYNOTFOUND);
    }

    /**
     * Test blank string storage and retrieval
     *
     * @depends testConnect
     */
    function testBlankStringTrans($b) {
        $key = $this->makeKey('blankStringTrans');

        $res = $b->upsert($key, '');
        $this->assertValidMetaDoc($res, 'cas');

        $res = $b->get($key);
        $this->assertValidMetaDoc($res, 'cas', 'flags');
        $this->assertEquals($res->value, '');
    }

    /**
     * Test handing NULL values
     *
     * @depends testConnect
     */
    function testEmptyNullValues($b) {
        $key = $this->makeKey('nullValue');
        $res = $b->upsert($key, null);
        $this->assertValidMetaDoc($res, 'cas');
        $res = $b->get($key);
        $this->assertValidMetaDoc($res, 'cas', 'flags');
        $this->assertEquals(null, $res->value);
    }

    /**
     * Test multi upsert
     *
     * @depends testConnect
     */
    function testMultiUpsert($b) {
        $keys = array(
            $this->makeKey('multiUpsert'),
            $this->makeKey('multiUpsert')
        );

        $res = $b->upsert(array(
            $keys[0] => array('value'=>'joe'),
            $keys[1] => array('value'=>'jack')
        ));

        $this->assertCount(2, $res);
        $this->assertValidMetaDoc($res[$keys[0]], 'cas');
        $this->assertValidMetaDoc($res[$keys[1]], 'cas');

        return $keys;
    }

    /**
     * Test multi upsert with the same keys
     *
     * @depends testConnect
     */
    function testMultiUpsertTheSameKey($b) {
        $key = $this->makeKey('multiUpsert');
        $keys = array($key, $key);

        $res = $b->upsert(array(
            $keys[0] => array('value'=>'joe'),
            $keys[1] => array('value'=>'jack')
        ));

        $this->assertCount(1, $res);
        $this->assertValidMetaDoc($res[$keys[0]], 'cas');
        $this->assertValidMetaDoc($res[$keys[1]], 'cas');
        $this->assertEquals($res[$keys[0]]->cas, $res[$keys[1]]->cas);

        return $keys;
    }

    /**
     * Test multi get
     *
     * @depends testConnect
     * @depends testMultiUpsert
     */
    function testMultiGet($b, $keys) {
        $res = $b->get($keys);

        $this->assertCount(2, $res);
        $this->assertValidMetaDoc($res[$keys[0]], 'value', 'flags', 'cas');
        $this->assertEquals($res[$keys[0]]->value, 'joe');
        $this->assertValidMetaDoc($res[$keys[1]], 'value', 'flags', 'cas');
        $this->assertEquals($res[$keys[1]]->value, 'jack');

        return $keys;
    }

    /**
     * Test multi remove
     *
     * @depends testConnect
     * @depends testMultiGet
     */
    function testMultiRemove($b, $keys) {
        $res = $b->remove($keys);

        $this->assertCount(2, $res);
        $this->assertValidMetaDoc($res[$keys[0]], 'cas');
        $this->assertValidMetaDoc($res[$keys[1]], 'cas');

        // This should throw a not-found exception
        $res = $b->get($keys);

        $this->assertCount(2, $res);

        // TODO: Different exceptions here might make sense.
        $this->assertErrorMetaDoc($res[$keys[0]], '\Couchbase\Exception', COUCHBASE_KEYNOTFOUND);
        $this->assertErrorMetaDoc($res[$keys[1]], '\Couchbase\Exception', COUCHBASE_KEYNOTFOUND);
    }

    /**
     * Test basic counter operations w/ an initial value
     *
     * @depends testConnect
     */
    function testCounterInitial($b) {
        $key = $this->makeKey('counterInitial');

        $res = $b->counter($key, +1, array('initial'=>1));
        $this->assertValidMetaDoc($res, 'value', 'cas');
        $this->assertEquals(1, $res->value);

        $res = $b->counter($key, +1);
        $this->assertValidMetaDoc($res, 'value', 'cas');
        $this->assertEquals(2, $res->value);

        $res = $b->counter($key, -1);
        $this->assertValidMetaDoc($res, 'value', 'cas');
        $this->assertEquals(1, $res->value);

        $b->remove($key);
    }

    /**
     * @test
     * Test counter operations on missing keys
     *
     * @depends testConnect
     */
    function testCounterBadKey($b) {
        $key = $this->makeKey('counterBadKey');

        $this->wrapException(function() use($b, $key) {
            $b->counter($key);
        }, '\Couchbase\Exception', COUCHBASE_KEYNOTFOUND);

        $this->wrapException(function() use($b, $key) {
            $b->counter($key, +1);
        }, '\Couchbase\Exception', COUCHBASE_KEYNOTFOUND);

        $res = $b->counter($key, -1, ['initial' => 42]);
        $this->assertValidMetaDoc($res, 'cas');
    }

    /**
     * Test expiry operations on keys
     *
     * @depends testConnect
     */
    function testExpiry($b) {
        $key = $this->makeKey('expiry');

        $b->upsert($key, 'dog', array('expiry' => 1));

        sleep(2);

        $this->wrapException(function() use($b, $key) {
            $b->get($key);
        }, '\Couchbase\Exception', COUCHBASE_KEYNOTFOUND);
    }

    /**
     * Test CAS works
     *
     * @depends testConnect
     */
    function testCas($b) {
        $key = $this->makeKey('cas');

        $res = $b->upsert($key, 'dog');
        $this->assertValidMetaDoc($res, 'cas');
        $old_cas = $res->cas;

        $res = $b->upsert($key, 'cat');
        $this->assertValidMetaDoc($res, 'cas');

        $this->wrapException(function() use($b, $key, $old_cas) {
            $b->replace($key, 'ferret', array('cas'=>$old_cas));
        }, '\Couchbase\Exception', COUCHBASE_KEYALREADYEXISTS);
    }

    /**
     * Test Locks work
     *
     * @depends testConnect
     */
    function testLocks($b) {
        $key = $this->makeKey('locks');

        $res = $b->upsert($key, 'jog');
        $this->assertValidMetaDoc($res, 'cas');

        // lock for 10 seconds
        $res = $b->getAndLock($key, 10);
        $this->assertValidMetaDoc($res, 'value', 'flags', 'cas');
        $lockedCas = $res->cas;

        $this->wrapException(function() use($b, $key) {
            // key is not accessible for locking
            $b->getAndLock($key, 1);
        }, '\Couchbase\Exception', COUCHBASE_TMPFAIL);

        $res = $b->unlock($key, ['cas' => $lockedCas]);

        // accessible for locking again
        $res = $b->getAndLock($key, 1);
        $this->assertValidMetaDoc($res, 'value', 'flags', 'cas');
    }

    /**
     * Test big upserts
     *
     * @depends testConnect
     */
    function testBigUpsert($b) {
        $key = $this->makeKey('bigUpsert');

        // $v = str_repeat("*", 0x1000000);
        $v = str_repeat("*", 0x100000);
        $res = $b->upsert($key, $v);

        $this->assertValidMetaDoc($res, 'cas');

        $b->remove($key);

        return $key;
    }

    /**
     * @test
     * Test upsert with no key specified
     *
     * @depends testConnect
     */
    function testNoKeyUpsert($b) {
        $this->wrapException(function() use($b) {
            $b->upsert('', 'joe');
        }, '\Couchbase\Exception', COUCHBASE_EMPTY_KEY);
    }

    /**
     * @test
     * Test recursive transcoder functions
     */
    function testRecursiveTranscode() {
        global $recursive_transcoder_bucket;
        global $recursive_transcoder_key2;
        global $recursive_transcoder_key3;

        $h = new \Couchbase\Cluster($this->testDsn);
        $h->authenticate($this->testAuthenticator);
        $b = $h->openBucket($this->testBucket);
        $this->setTimeouts($b);

        $key1 = $this->makeKey('basicUpsertKey1');
        $key2 = $this->makeKey('basicUpsertKey2');
        $key3 = $this->makeKey('basicUpsertKey3');

        // Set up a transcoder that upserts key2 when it sees key1
        $recursive_transcoder_bucket = $b;
        $recursive_transcoder_key2 = $key2;
        $recursive_transcoder_key3 = $key3;
        $b->setTranscoder(
            'recursive_transcoder_encoder',  // defined at bottom of file
            'recursive_transcoder_decoder'); // defined at bottom of file

        // Upsert key1, transcoder should set key2
        $res = $b->upsert($key1, 'key1');
        $this->assertValidMetaDoc($res, 'cas');

        // Check key1 was upserted
        $res = $b->get($key1);
        $this->assertValidMetaDoc($res, 'cas');
        $this->assertEquals($res->value, 'key1');

        // Check key2 was upserted, trasncoder should set key3
        $res = $b->get($key2);
        $this->assertValidMetaDoc($res, 'cas');
        $this->assertEquals($res->value, 'key2');

        // Check key3 was upserted
        $res = $b->get($key3);
        $this->assertValidMetaDoc($res, 'cas');
        $this->assertEquals($res->value, 'key3');
    }

    /**
     * Test all option values to make sure they save/load
     * We open a new bucket for this test to make sure our settings
     * changes do not affect later tests. Console log level option used
     * to generate unique (for these test suites) connection string,
     * so that the lcb_t won't be reused from the pool
     */
    function testOptionVals() {
        $h = new \Couchbase\Cluster($this->testDsn . "?console_log_level=42");
        $h->authenticate($this->testAuthenticator);
        $b = $h->openBucket($this->testBucket);

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
    function testLookupInFulldoc($b) {
        if ($this->serverVersion() < 5) {
            $this->markTestSkipped("Subdoc FullDocument not available for {$this->serverVersion()}");
        }
        $key = $this->makeKey('lookup_in_fulldoc');
        $b->upsert($key, ['path1' => 42, 'path2' => 'foo']);

        $result = $b->lookupIn($key)
                ->get()
                ->get('path2')
                ->execute();
        $this->assertNull($result->error);
        $this->assertEquals(2, count($result->value));
        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[0]['code']);
        $this->assertEquals(['path1' => 42, 'path2' => 'foo'], $result->value[0]['value']);
        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[1]['code']);
        $this->assertEquals('foo', $result->value[1]['value']);
    }

    /**
     * @depends testConnect
     */
    function testLookupIn($b) {
        $key = $this->makeKey('lookup_in');
        $b->upsert($key, array('path1' => 'value1'));

        $result = $b->retrieveIn($key, 'path1');
        $this->assertEquals(1, count($result->value));
        $this->assertEquals('value1', $result->value[0]['value']);
        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[0]['code']);
        $this->assertNotEmpty($result->cas);

        # Try when path is not found
        $result = $b->retrieveIn($key, 'path2');
        $this->assertInstanceOf('\Couchbase\Exception', $result->error);
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(null, $result->value[0]['value']);
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_ENOENT, $result->value[0]['code']);

        # Try when there is a mismatch
        $result = $b->retrieveIn($key, 'path1[0]');
        $this->assertInstanceOf('\Couchbase\Exception', $result->error);
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(null, $result->value[0]['value']);
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_MISMATCH, $result->value[0]['code']);

        # Try existence
        $result = $b->lookupIn($key)->exists('path1')->execute();
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[0]['code']);

        # Not found
        $result = $b->lookupIn($key)->exists('p')->execute();
        $this->assertInstanceOf('\Couchbase\Exception', $result->error);
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_ENOENT, $result->value[0]['code']);


        # Insert a non-JSON document
        $key = $this->makeKey('lookup_in_nonjson');
        $b->upsert($key, 'value');

        $result = $b->lookupIn($key)->exists('path')->execute();
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_DOC_NOTJSON, $result->value[0]['code']);

        # Try on non-existing document. Should fail
        $key = $this->makeKey('lookup_in_with_missing_key');
        $result = $b->lookupIn($key)->exists('path')->execute();
        $this->assertEquals(NULL, $result->value);
        $this->assertInstanceOf('\Couchbase\Exception', $result->error);
        $this->assertEquals(COUCHBASE_KEY_ENOENT, $result->error->getCode());
    }

    /**
     * @depends testConnect
     */
    function testGetCount($b) {
        if ($this->serverVersion() < 5) {
            $this->markTestSkipped("Subdoc GET_COUNT not available for {$this->serverVersion()}");
        }

        $key = $this->makeKey('get_count');
        $b->upsert($key, ['list' => [1, 2, 42], 'object' => ['foo' => 42]]);

        # Try existence
        $result = $b->lookupIn($key)
                ->getCount('list')
                ->getCount('object')
                ->execute();
        $this->assertEquals(2, count($result->value));
        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[0]['code']);
        $this->assertEquals(3, $result->value[0]['value']);
        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[1]['code']);
        $this->assertEquals(1, $result->value[1]['value']);
    }

    /**
     * @expectedException \Couchbase\Exception
     * @expectedExceptionMessageRegExp /EMPTY_PATH/
     * @depends testConnect
     */
    function testLookupInWithEmptyPath($b) {
        $key = $this->makeKey('lookup_in_with_empty_path');
        $b->upsert($key, array('path1' => 'value1'));

        $result = $b->lookupIn($key)->exists('')->execute();
    }

    /**
     * @depends testConnect
     */
    function testMutateInWithExpiry($b) {
        $key = $this->makeKey('mutate_in_with_expiry');
        $key = 'mutate_in_with_expiry';
        $b->upsert($key, new stdClass());
        $result = $b->mutateIn($key)
                ->withExpiry(1) // should expire in one second
                ->upsert('foo', 'bar')
                ->execute();
        $this->assertNull($result->error);

        sleep(2);

        $this->wrapException(function() use($b, $key) {
            $res = $b->get($key);
            var_dump($res);
            var_dump($b);
        }, '\Couchbase\Exception', COUCHBASE_KEYNOTFOUND);
    }

    /**
     * @depends testConnect
     */
    function testMutateInFulldoc($b) {
        if ($this->serverVersion() < 5) {
            $this->markTestSkipped("Subdoc FullDocument not available for {$this->serverVersion()}");
        }
        $key = $this->makeKey('mutate_in_fulldoc');

        $result = $b->mutateIn($key)
                ->upsert('created_at', time(), ['xattr' => true, 'createPath' => true])
                ->upsert(["new" => "yes"])
                ->modeDocument(\Couchbase\MutateInBuilder::FULLDOC_UPSERT)
                ->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'new');
        $this->assertEquals("yes", $result->value[0]['value']);

        $result = $b->mutateIn($key)
                ->upsert('created_at', time(), ['xattr' => true, 'createPath' => true])
                ->upsert(["duplicate" => "yes"])
                ->modeDocument(\Couchbase\MutateInBuilder::FULLDOC_INSERT)
                ->execute();
        $this->assertNotNull($result->error);
        $this->assertEquals(COUCHBASE_KEY_EEXISTS, $result->error->getCode());

        $result = $b->mutateIn($key)
                ->upsert('updated_at', time(), ['xattr' => true, 'createPath' => true])
                ->upsert(["updated" => "yes"])
                ->modeDocument(\Couchbase\MutateInBuilder::FULLDOC_REPLACE)
                ->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'updated');
        $this->assertEquals("yes", $result->value[0]['value']);
    }

    /**
     * @depends testConnect
     */
    function testMutateIn($b) {
        $key = $this->makeKey('mutate_in');
        $b->upsert($key, new stdClass());

        $result = $b->mutateIn($key)->upsert('newDict', array('hello'))->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'newDict');
        $this->assertEquals(array('hello'), $result->value[0]['value']);

        # Does not create deep path without create_parents
        $result = $b->mutateIn($key)->upsert('path.with.missing.parents', 'value')->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_ENOENT, $result->value[0]['code']);

        # Creates deep path without create_parents
        $result = $b->mutateIn($key)->upsert('path.with.missing.parents', 'value', true)->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'path.with.missing.parents');
        $this->assertEquals('value', $result->value[0]['value']);

        $this->assertNotEmpty($result->cas);
        $cas = $result->cas;

        $result = $b->mutateIn($key, $cas . 'X')->upsert('newDict', 'withWrongCAS')->execute();
        $this->assertEquals(COUCHBASE_KEY_EEXISTS, $result->error->getCode());
        $this->assertEquals(NULL, $result->value);
        # once again with correct CAS
        $result = $b->mutateIn($key, $cas)->upsert('newDict', 'withCorrectCAS')->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'newDict');
        $this->assertEquals('withCorrectCAS', $result->value[0]['value']);

        # insert into existing path should fail
        $result = $b->mutateIn($key)->insert('newDict', array('foo' => 42))->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_EEXISTS, $result->value[0]['code']);

        # insert into new path should succeed
        $result = $b->mutateIn($key)->insert('anotherDict', array('foo' => 42))->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'anotherDict');
        $this->assertEquals(array('foo' => 42), $result->value[0]['value']);

        # replace of existing path should not fail
        $result = $b->mutateIn($key)->replace('newDict', array(42 => 'foo'))->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'newDict');
        $this->assertEquals(array(42 => 'foo'), $result->value[0]['value']);

        # replace of missing path should not fail
        $result = $b->mutateIn($key)->replace('missingDict', array(42 => 'foo'))->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_ENOENT, $result->value[0]['code']);

        $result = $b->mutateIn($key)->upsert('empty', '')->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'empty');
        $this->assertEquals('', $result->value[0]['value']);

        $result = $b->mutateIn($key)->upsert('null', null)->execute();
        $this->assertNull($result->error);
        $result = $b->retrieveIn($key, 'null');
        $this->assertEquals(null, $result->value[0]['value']);

        $result = $b->mutateIn($key)->upsert('array', array(1, 2, 3))->execute();
        $this->assertNull($result->error);

        $result = $b->mutateIn($key)->upsert('array.newKey', 'newVal')->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_MISMATCH, $result->value[0]['code']);

        $result = $b->mutateIn($key)->upsert('array[0]', 'newVal')->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_EINVAL, $result->value[0]['code']);

        $result = $b->mutateIn($key)->upsert('array[3].bleh', 'newVal')->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_ENOENT, $result->value[0]['code']);
    }

    /**
     * @expectedException \Couchbase\Exception
     * @expectedExceptionMessageRegExp /EMPTY_PATH/
     * @depends testConnect
     */
    function testMutationInWithEmptyPath($b) {
        $key = $this->makeKey('lookup_in_with_empty_path');
        $b->upsert($key, array('path1' => 'value1'));

        $result = $b->mutateIn($key)->upsert('', 'value')->execute();
    }

    /**
     * @depends testConnect
     */
    function testCounterIn($b) {
        $key = $this->makeKey('mutate_in');
        $b->upsert($key, new stdClass());

        $result = $b->mutateIn($key)->counter('counter', 100)->execute();
        $this->assertNull($result->error);
        $this->assertNotEmpty($result->cas);
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(100, $result->value[0]['value']);

        $result = $b->mutateIn($key)->upsert('not_a_counter', 'foobar')->execute();
        $this->assertNull($result->error);

        $result = $b->mutateIn($key)->counter('not_a_counter', 100)->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_MISMATCH, $result->value[0]['code']);

        $result = $b->mutateIn($key)->counter('path.to.new.counter', 100)->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_ENOENT, $result->value[0]['code']);

        $result = $b->mutateIn($key)->counter('path.to.new.counter', 100, true)->execute();
        $this->assertNull($result->error);
        $this->assertNotEmpty($result->cas);
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(100, $result->value[0]['value']);

        $result = $b->mutateIn($key)->counter('counter', -25)->execute();
        $this->assertNull($result->error);
        $this->assertNotEmpty($result->cas);
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(75, $result->value[0]['value']);

        $result = $b->mutateIn($key)->counter('counter', 0)->execute();
        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_BAD_DELTA, $result->value[0]['code']);
    }

    /**
     * @depends testConnect
     */
    function testMultiLookupIn($b) {
        $key = $this->makeKey('multi_lookup_in');
        $b->upsert($key, array(
            'field1' => 'value1',
            'field2' => 'value2',
            'array' =>  array(1, 2, 3),
            'boolean' => false,
        ));

        $result = $b->lookupIn($key)
                ->get('field1')
                ->exists('field2')
                ->exists('field3')
                ->execute();

        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(3, count($result->value));

        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[0]['code']);
        $this->assertEquals('value1', $result->value[0]['value']);

        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[1]['code']);
        $this->assertEquals(null, $result->value[1]['value']);

        $this->assertEquals(COUCHBASE_SUBDOC_PATH_ENOENT, $result->value[2]['code']);
        $this->assertEquals(null, $result->value[2]['value']);
    }

    /**
     * @depends testConnect
     */
    function testMultiMutateIn($b) {
        $key = $this->makeKey('multi_mutate_in');
        $b->upsert($key, array(
            'field1' => 'value1',
            'field2' => 'value2',
            'array' =>  array(1, 2, 3),
        ));

        $result = $b->mutateIn($key)
                ->replace('field1', array('foo' => 'bar'))
                ->remove('array')
                ->replace('missing', "hello world")
                ->execute();

        $this->assertEquals(COUCHBASE_SUBDOC_MULTI_FAILURE, $result->error->getCode());
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUBDOC_PATH_ENOENT, $result->value[2]['code']);
    }

    /**
     * @depends testConnect
     */
    function testMultiValue($b) {
        $key = $this->makeKey('multi_value');
        $b->upsert($key, array('array' => array()));

        $result = $b->mutateIn($key)->arrayAppend('array', true)->execute();
        $this->assertNull($result->error);

        $result = $b->retrieveIn($key, 'array');
        $this->assertNull($result->error);
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(array(true), $result->value[0]['value']);

        $result = $b->mutateIn($key)->arrayAppendAll('array', array(1, 2, 3))->execute();
        $this->assertNull($result->error);

        $result = $b->retrieveIn($key, 'array');
        $this->assertNull($result->error);
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(array(true, 1, 2, 3), $result->value[0]['value']);

        $result = $b->mutateIn($key)->arrayPrepend('array', array(42))->execute();
        $this->assertNull($result->error);

        $result = $b->retrieveIn($key, 'array');
        $this->assertNull($result->error);
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(array(array(42), true, 1, 2, 3), $result->value[0]['value']);
    }

    /**
     * @depends testConnect
     */
    function testSubdocAttributes($b) {
        if ($this->serverVersion() < 5) {
            $this->markTestSkipped("Subdoc attributes are not supported, skipping the test");
        }
        $key = $this->makeKey('subdoc_attributes');
        $b->upsert($key, ['foo' => 'bar']);

        $result = $b->mutateIn($key)
                ->upsert('app.created_by', ['name' => 'John Doe', 'role' => 'DB administrator'],
                         ['xattr' => true, 'createPath' => true])
                ->execute();
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[0]['code']);

        $result = $b->lookupIn($key)
                ->get('app.created_by', ['xattr' => true, 'createPath' => true])
                ->execute();
        $this->assertEquals(1, count($result->value));
        $this->assertEquals(COUCHBASE_SUCCESS, $result->value[0]['code']);
        $this->assertEquals(['name' => 'John Doe', 'role' => 'DB administrator'], $result->value[0]['value']);
    }
}

function libcouchbase_version() {
    $ext = new ReflectionExtension('couchbase');
    ob_start();
    $ext->info();
    $data = ob_get_contents();
    ob_end_clean();
    preg_match('/libcouchbase runtime version => (\d+\.\d+\.\d+)/', $data, $matches);
    return $matches[1];
}

function recursive_transcoder_encoder($value) {
    global $recursive_transcoder_bucket;
    global $recursive_transcoder_key2;
    if ($value == 'key1') {
        $recursive_transcoder_bucket->upsert(
            $recursive_transcoder_key2, 'key2');
    }
    return couchbase_default_encoder($value);
}

function recursive_transcoder_decoder($bytes, $flags, $datatype) {
    global $recursive_transcoder_bucket;
    global $recursive_transcoder_key3;
    $value = couchbase_default_decoder($bytes, $flags, $datatype);
    if ($value == 'key2') {
        $recursive_transcoder_bucket->upsert(
            $recursive_transcoder_key3, 'key3');
    }
    return $value;
}
