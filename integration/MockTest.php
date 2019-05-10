<?php

require_once('tests/CouchbaseMock.php');

const ERRCODE_CONSTANT = 0x7ff0;
const ERRCODE_LINEAR = 0x7ff1;
const ERRCODE_EXPONENTIAL = 0x7ff2;

class MockTest extends \PHPUnit_Framework_TestCase {

    protected $mock;

    protected function setUp() {
        $this->mock = CouchbaseMock::get();
        $this->mock->start();
        $this->mock->setCCCP(true);
    }

    protected function tearDown() {
        $this->mock->stop();
    }

    protected function checkRetryVerify($errorCode) {
        $cluster = new \Couchbase\Cluster($this->mock->connectionString(['enable_errmap' => true]));
        $bucket = $cluster->openBucket('default');

        // Establish data connection
        $bucket->upsert('key', 'var');

        $serverIdx = $this->mock->masterForKey('key');
        $this->mock->startRetryVerify($serverIdx);
        $this->mock->operationFailure($errorCode, -1, $serverIdx);

        $seenException = false;
        try {
            $bucket->upsert('key', 'var');
        } catch (\Couchbase\Exception $ex) {
            if ($ex->getCode() == COUCHBASE_GENERIC_TMPERR) {
                $seenException = true;
            }
        }
        $this->assertTrue($seenException, 'Expected upsert operation fail with COUCHBASE_GENERIC_TMPERR');

        $opcode = 0x01; // PROTOCOL_BINARY_CMD_SET
        $this->mock->checkRetryVerify($errorCode, $serverIdx, $opcode, 20);
    }

    public function testRetryVerifyConstant() {
        $this->checkRetryVerify(ERRCODE_CONSTANT);
    }

    public function testRetryVerifyLinear() {
        $this->checkRetryVerify(ERRCODE_LINEAR);
    }

    public function testRetryVerifyExponential() {
        $this->checkRetryVerify(ERRCODE_EXPONENTIAL);
    }
}
