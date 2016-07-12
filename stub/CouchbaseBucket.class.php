<?php
/**
 * File for the CouchbaseBucket class.
 *
 * @author Brett Lawson <brett19@gmail.com>
 */

/**
 * Represents a bucket connection.
 *
 * Note: This class must be constructed by calling the openBucket
 * method of the CouchbaseCluster class.
 *
 * @property integer $operationTimeout
 * @property integer $viewTimeout
 * @property integer $durabilityInterval
 * @property integer $durabilityTimeout
 * @property integer $httpTimeout
 * @property integer $configTimeout
 * @property integer $configDelay
 * @property integer $configNodeTimeout
 * @property integer $htconfigIdleTimeout
 *
 * @package Couchbase
 *
 * @see CouchbaseCluster::openBucket()
 */
class CouchbaseBucket {
    /**
     * @var _CouchbaseBucket
     * @ignore
     *
     * Pointer to our C binding backing class.
     */
    private $me;

    /**
     * @var string
     * @ignore
     *
     * The name of the bucket this object represents.
     */
    private $name;

    /**
     * @var _CouchbaseCluster
     * @ignore
     *
     * Pointer to a manager instance if there is one.
     */
    private $_manager;

    /**
     * @var array
     * @ignore
     *
     * A list of N1QL nodes to query.
     */
    private $queryhosts = NULL;

    private $authenticator;

    /**
     * Constructs a bucket connection.
     *
     * @private
     * @ignore
     *
     * @param string $connstr A cluster connection string to connect with.
     * @param string $name The name of the bucket to connect to.
     * @param string $password The password to authenticate with.
     *
     * @private
     */
    public function __construct($connstr, $name, $password, $authenticator = null) {
        $this->me = new _CouchbaseBucket($connstr, $name, $password);
        $this->me->setTranscoder("couchbase_default_encoder", "couchbase_default_decoder");
        $this->name = $name;
        $this->authenticator = $authenticator;
    }

    /**
     * Returns bucket name
     *
     * @return string name of the bucket
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Returns an instance of a CouchbaseBucketManager for performing management
     * operations against a bucket.
     *
     * @return CouchbaseBucketManager
     */
    public function manager() {
        if (!$this->_manager) {
            $this->_manager = new CouchbaseBucketManager(
                $this->me, $this->name);
        }
        return $this->_manager;
    }

    /**
     * Enables N1QL support on the client.  A cbq-server URI must be passed.
     * This method will be deprecated in the future in favor of automatic
     * configuration through the connected cluster.
     *
     * @param $hosts An array of host/port combinations which are N1QL servers
     * attached to the cluster.
     */
    public function enableN1ql($hosts) {
        if (is_array($hosts)) {
            $this->queryhosts = $hosts;
        } else {
            $this->queryhosts = array($hosts);
        }
    }

    /**
     * Inserts a document.  This operation will fail if
     * the document already exists on the cluster.
     *
     * @param string|array $ids
     * @param mixed $val
     * @param array $options expiry(integer), persist_to(integer), replicate_to(integer)
     * @return mixed
     */
    public function insert($ids, $val = NULL, $options = array()) {
        return $this->me->insert($ids, $val, $options);
    }

    /**
     * Inserts or updates a document, depending on whether the
     * document already exists on the cluster.
     *
     * @param string|array $ids
     * @param mixed $val
     * @param array $options expiry(integer), persist_to(integer), replicate_to(integer)
     * @return mixed
     */
    public function upsert($ids, $val = NULL, $options = array()) {
        return $this->me->upsert($ids, $val, $options);
    }

    /**
     * Replaces a document.
     *
     * @param string|array $ids
     * @param mixed $val
     * @param array $options cas(string), expiry(integer), persist_to(integer), replicate_to(integer)
     * @return mixed
     */
    public function replace($ids, $val = NULL, $options = array()) {
        return $this->me->replace($ids, $val, $options);
    }

    /**
     * Appends content to a document.
     *
     * @param string|array $ids
     * @param mixed $val
     * @param array $options cas(string), persist_to(integer), replicate_to(integer)
     * @return mixed
     */
    public function append($ids, $val = NULL, $options = array()) {
        return $this->me->append($ids, $val, $options);
    }

    /**
     * Prepends content to a document.
     *
     * @param string|array $ids
     * @param mixed $val
     * @param array $options cas(string), persist_to(integer), replicate_to(integer)
     * @return mixed
     */
    public function prepend($ids, $val = NULL, $options = array()) {
        return $this->me->prepend($ids, $val, $options);
    }

    /**
     * Deletes a document.
     *
     * @param string|array $ids
     * @param array $options cas(string), persist_to(integer), replicate_to(integer)
     * @return mixed
     */
    public function remove($ids, $options = array()) {
        return $this->_endure($ids, $options,
            $this->me->remove($ids, $options));
    }

    /**
     * Retrieves a document.
     *
     * @param string|array $ids
     * @param array $options lock(integer), expiry(integer)
     * @return mixed
     */
    public function get($ids, $options = array()) {
        return $this->me->get($ids, $options);
    }

    /**
     * Retrieves a document and simultaneously updates its expiry.
     *
     * @param string $id
     * @param integer $expiry
     * @param array $options
     * @return mixed
     */
    public function getAndTouch($id, $expiry, $options = array()) {
        $options['expiry'] = $expiry;
        return $this->me->get($id, $options);
    }

    /**
     * Retrieves a document and locks it.
     *
     * @param string $id
     * @param integer $lockTime
     * @param array $options
     * @return mixed
     */
    public function getAndLock($id, $lockTime, $options = array()) {
        $options['lockTime'] = $lockTime;
        return $this->me->get($id, $options);
    }

    /**
     * Retrieves a document from a replica.
     *
     * @param string $id
     * @param array $options index(integer)
     * @return mixed
     */
    public function getFromReplica($id, $options = array()) {
        return $this->me->getFromReplica($id, $options);
    }

    /**
     * Updates a documents expiry.
     *
     * @param string $id
     * @param integer $expiry
     * @param array $options
     * @return mixed
     */
    public function touch($id, $expiry, $options = array()) {
        return $this->me->touch($id, $expiry, $options);
    }

    /**
     * Increment or decrements a key (based on $delta).
     *
     * @param string|array $ids
     * @param integer $delta
     * @param array $options initial(integer), expiry(integer)
     * @return mixed
     */
    public function counter($ids, $delta, $options = array()) {
        return $this->_endure($ids, $options,
            $this->me->counter($ids, $delta, $options));
    }

    /**
     * Unlocks a key previous locked with a call to get().
     * @param string|array $ids
     * @param array $options cas(string)
     * @return mixed
     */
    public function unlock($ids, $options = array()) {
        return $this->me->unlock($ids, $options);
    }

    /**
     * Executes a view query.
     *
     * @param ViewQuery $queryObj
     * @return mixed
     * @throws CouchbaseException
     *
     * @internal
     */
    public function _view($queryObj, $json_asarray) {
        $path = $queryObj->toString();
        $res = $this->me->http_request(1, 1, $path, NULL, 1);
        $out = json_decode($res, $json_asarray);
        if ($json_asarray) {
            if (isset($out['error'])) {
                throw new CouchbaseException($out['error'] . ': ' . $out['reason']);
            }
        } else {
            if (isset($out->error)) {
                throw new CouchbaseException($out->error . ': ' . $out->reason);
            }
        }
        return $out;
    }

    /**
     * Performs a N1QL query.
     *
     * @param CouchbaseN1qlQuery $queryObj
     * @return mixed
     * @throws CouchbaseException
     *
     * @internal
     */
    public function _n1ql($queryObj, $json_asarray) {
        $data = $queryObj->options;
        $dataStr = json_encode($data, true);
        $dataOut = $this->me->n1ql_request($dataStr, $queryObj->adhoc);

        $meta = json_decode($dataOut['meta'], true);
        if (isset($meta['errors']) && count($meta['errors']) > 0) {
            $err = $meta['errors'][0];
            $ex = new CouchbaseException($err['msg']);
            $ex->qCode = $err['code'];
            throw $ex;
        }

        $rows = array();
        foreach ($dataOut['results'] as $row) {
            $rows[] = json_decode($row, $json_asarray);
        }
        $result = array(
            'rows' => $rows,
            'status' => $meta['status'],
            'metrics' => $meta['metrics']
        );

        if ( ! $json_asarray) {
            return (object)$result;
        }

        return $result;
    }

    public function _search($queryObj, $json_asarray) {
        $dataIn = json_encode($queryObj->export());
        $dataOut = $this->me->fts_request($dataIn);

        $meta = json_decode($dataOut['meta'], true);
        if (isset($meta['errors']) && count($meta['errors']) > 0) {
            throw new CouchbaseException(json_encode($meta['errors']));
        }

        $hits = array();
        foreach ($dataOut['results'] as $row) {
            $hits[] = json_decode($row, $json_asarray);
        }
        $result = array(
            'hits' => $hits,
            'status' => $meta['status'],
            'metrics' => array(
                'total_hits' => $meta['total_hits'],
                'took' => $meta['took'],
                'max_score' => $meta['max_score']
            )
        );
        if (isset($meta['facets'])) {
            $result['facets'] = $meta['facets'];
        }

        if ( ! $json_asarray) {
            return (object)$result;
        }

        return $result;
    }

    /**
     * Performs a query (either ViewQuery or N1qlQuery).
     *
     * @param CouchbaseQuery $query
     * @return mixed
     * @throws CouchbaseException
     */
    public function query($query, $json_asarray = false) {
        if ($query instanceof _CouchbaseDefaultViewQuery ||
            $query instanceof _CouchbaseSpatialViewQuery) {
            return $this->_view($query, $json_asarray);
        } else if ($query instanceof CouchbaseN1qlQuery) {
            return $this->_n1ql($query, $json_asarray);
        } else if ($query instanceof CouchbaseSearchQuery) {
            return $this->_search($query, $json_asarray);
        } else {
            throw new CouchbaseException(
                'Passed object must be of type ViewQuery, N1qlQuery or SearchQuery');
        }
    }

    /**
     * Creates a CouchbaseLookupInBuilder object with which you can then use method-chaining
     * to populate them with lookup operations and then later execute.
     *
     * @param string $id
     * @return CouchbaseLookupInBuilder
     */
    public function lookupIn($id) {
        return new CouchbaseLookupInBuilder($this, $id);
    }

    /**
     * Shortcut to alternative to constructing a builder for getting multiple
     * paths in the document.
     *
     * @param string $id
     * @param string ...$keys
     */
    public function retrieveIn($id) {
        $builder = new CouchbaseLookupInBuilder($this, $id);
        $args = func_get_args();
        for ($i = 1; $i < func_num_args(); $i++) {
            $builder->get($args[$i]);
        }
        return $builder->execute();
    }

    /**
     * Creates a CouchbaseMutateInBuilder object with which you can then use method-chaining
     * to populate them with mutation operations and then later execute.
     *
     * @param string $id
     * @param string $cas
     * @return CouchbaseMutateInBuilder
     */
    public function mutateIn($id, $cas = null) {
        return new CouchbaseMutateInBuilder($this, $id, $cas);
    }

    /**
     * Function, which performs subdocument calls
     *
     * @internal
     *
     * @param string $id
     * @param array $commands list of commands from builder
     * @param string $cas CAS value for mutations
     */
    public function _subdoc($id, $commands, $cas = null) {
        return $this->me->subdoc_request($id, $commands, $cas);
    }

    /**
     * Sets custom encoder and decoder functions for handling serialization.
     *
     * @param string $encoder The encoder function name
     * @param string $decoder The decoder function name
     */
    public function setTranscoder($encoder, $decoder) {
        return $this->me->setTranscoder($encoder, $decoder);
    }

    /**
     * Ensures durability requirements are met for an executed
     *  operation.  Note that this function will automatically
     *  determine the result types and check for any failures.
     *
     * @private
     * @ignore
     *
     * @param $id
     * @param $res
     * @param $options
     * @return mixed
     * @throws Exception
     */
    private function _endure($id, $options, $res) {
        if ((!isset($options['persist_to']) || !$options['persist_to']) &&
            (!isset($options['replicate_to']) || !$options['replicate_to'])) {
            return $res;
        }
        if (is_array($res)) {
            // Build list of keys to check
            $chks = array();
            foreach ($res as $key => $result) {
                if (!$result->error) {
                    $chks[$key] = array(
                        'cas' => $result->cas
                    );
                }
            }

            // Do the checks
            $dres = $this->me->durability($chks, array(
                'persist_to' => $options['persist_to'],
                'replicate_to' => $options['replicate_to']
            ));

            // Copy over the durability errors
            foreach ($dres as $key => $result) {
                if (!$result) {
                    $res[$key]->error = $result->error;
                }
            }

            return $res;
        } else {
            if ($res->error) {
                return $res;
            }

            $dres = $this->me->durability($id, array(
                'cas' => $res->cas,
                'persist_to' => $options['persist_to'],
                'replicate_to' => $options['replicate_to']
            ));

            return $res;
        }
    }

    /**
     * Magic function to handle the retrieval of various properties.
     *
     * @internal
     */
    public function __get($name) {
        if ($name == 'operationTimeout') {
            return $this->me->getOption(COUCHBASE_CNTL_OP_TIMEOUT);
        } else if ($name == 'viewTimeout') {
            return $this->me->getOption(COUCHBASE_CNTL_VIEW_TIMEOUT);
        } else if ($name == 'durabilityInterval') {
            return $this->me->getOption(COUCHBASE_CNTL_DURABILITY_INTERVAL);
        } else if ($name == 'durabilityTimeout') {
            return $this->me->getOption(COUCHBASE_CNTL_DURABILITY_TIMEOUT);
        } else if ($name == 'httpTimeout') {
            return $this->me->getOption(COUCHBASE_CNTL_HTTP_TIMEOUT);
        } else if ($name == 'configTimeout') {
            return $this->me->getOption(COUCHBASE_CNTL_CONFIGURATION_TIMEOUT);
        } else if ($name == 'configDelay') {
            return $this->me->getOption(COUCHBASE_CNTL_CONFDELAY_THRESH);
        } else if ($name == 'configNodeTimeout') {
            return $this->me->getOption(COUCHBASE_CNTL_CONFIG_NODE_TIMEOUT);
        } else if ($name == 'htconfigIdleTimeout') {
            return $this->me->getOption(COUCHBASE_CNTL_HTCONFIG_IDLE_TIMEOUT);
        }

        $trace = debug_backtrace();
        trigger_error(
            'Undefined property via __get(): ' . $name .
            ' in ' . $trace[0]['file'] .
            ' on line ' . $trace[0]['line'],
            E_USER_NOTICE);
        return null;
    }

    /**
     * Magic function to handle the setting of various properties.
     *
     * @internal
     */
    public function __set($name, $value) {
        if ($name == 'operationTimeout') {
            return $this->me->setOption(COUCHBASE_CNTL_OP_TIMEOUT, $value);
        } else if ($name == 'viewTimeout') {
            return $this->me->setOption(COUCHBASE_CNTL_VIEW_TIMEOUT, $value);
        } else if ($name == 'durabilityInterval') {
            return $this->me->setOption(COUCHBASE_CNTL_DURABILITY_INTERVAL, $value);
        } else if ($name == 'durabilityTimeout') {
            return $this->me->setOption(COUCHBASE_CNTL_DURABILITY_TIMEOUT, $value);
        } else if ($name == 'httpTimeout') {
            return $this->me->setOption(COUCHBASE_CNTL_HTTP_TIMEOUT, $value);
        } else if ($name == 'configTimeout') {
            return $this->me->setOption(COUCHBASE_CNTL_CONFIGURATION_TIMEOUT, $value);
        } else if ($name == 'configDelay') {
            return $this->me->setOption(COUCHBASE_CNTL_CONFDELAY_THRESH, $value);
        } else if ($name == 'configNodeTimeout') {
            return $this->me->setOption(COUCHBASE_CNTL_CONFIG_NODE_TIMEOUT, $value);
        } else if ($name == 'htconfigIdleTimeout') {
            return $this->me->setOption(COUCHBASE_CNTL_HTCONFIG_IDLE_TIMEOUT, $value);
        }

        $trace = debug_backtrace();
        trigger_error(
            'Undefined property via __set(): ' . $name .
            ' in ' . $trace[0]['file'] .
            ' on line ' . $trace[0]['line'],
            E_USER_NOTICE);
        return null;
    }
}

class CouchbaseMutationState {
    /**
     * @var array
     */
    private $tokens = array();

    public static function from($source = array()) {
        $state = new CouchbaseMutationState();
        $state->add($source);
        return $state;
    }

    public function add($source = array()) {
        if (count($source) < 1) {
            throw new InvalidArgumentException("At least one document or fragment must be provided");
        }
        foreach ($source as $doc) {
            $this->addToken($doc->token);
        }
    }

    public function exportForN1ql() {
        $result = array();
        foreach ($this->tokens as $token) {
            if (!array_key_exists($token->bucket, $this->tokens)) {
                $result[$token->bucket] = array();
            }
            $bucket = &$result[$token->bucket];
            $bucket[$token->vbucketID] = array($token->sequenceNumber, $token->vbucketUUID);
        }
        return $result;
    }

    public function exportForSearch() {
        $result = array();
        foreach ($this->tokens as $token) {
            $tokenKey = $token->vbucketID . '/' . $token->vbucketUUID;
            $oldSeqno = $result[$tokenKey];
            if ($oldSeqno < $token->sequenceNumber) {
                $result[$tokenKey] = $token->sequenceNumber;
            }
        }
        return $result;
    }

    private function addToken($newToken) {
        for ($i = 0; $i < count($this->tokens); $i++) {
            $token = $this->tokens[$i];
            if ($token->vbucketID == $newToken->vbucketID && $token->bucket == $newToken->bucket) {
                $this->tokens[$i] = $newToken;
                return;
            }
        }
        array_push($this->tokens, $newToken);
    }
}
