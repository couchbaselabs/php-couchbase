<?php
/**
 * File for the CouchbaseBucketManager class.
 * @author Brett Lawson <brett19@gmail.com>
 */

/**
 * Class exposing the various available management operations that can be
 * performed on a bucket.
 *
 * @package Couchbase
 */
class CouchbaseBucketManager {
    /**
     * @var _CouchbaseBucket
     * @ignore
     *
     * Pointer to our C binding backing class.
     */
    private $_me;

    /**
     * @var string
     * @ignore
     *
     * Name of the bucket we are managing
     */
    private $_name;

    /**
     * @private
     * @ignore
     *
     * @param string $binding
     * @param string $name
     */
    public function __construct($binding, $name) {
        $this->_me = $binding;
        $this->_name = $name;
    }

    /**
     * Returns all the design documents for this bucket.
     *
     * @return mixed
     */
    public function getDesignDocuments() {
        $path = "/pools/default/buckets/" . $this->_name . '/ddocs';
        $res = $this->_me->http_request(2, 1, $path, NULL, 2);
        $ddocs = array();
        $data = json_decode($res, true);
        foreach ($data['rows'] as $row) {
            $name = substr($row['doc']['meta']['id'], 8);
            $ddocs[$name] = $row['doc']['json'];
        }
        return $ddocs;
    }

    /**
     * Inserts a design document to this bucket.  Failing if a design
     * document with the same name already exists.
     *
     * @param string $name Name of the design document.
     * @param string $data The design document data.
     * @throws CouchbaseException
     * @return boolean
     */
    public function insertDesignDocument($name, $data) {
        if ($this->getDesignDocument($name)) {
            throw new CouchbaseException('design document already exists');
        }
        return $this->upsertDesignDocument($name, $data);
    }

    /**
     * Inserts a design document to this bucket.  Overwriting any existing
     * design document with the same name.
     *
     * @param string $name Name of the design document.
     * @param string $data The design document data.
     * @return boolean
     */
    public function upsertDesignDocument($name, $data) {
        $path = '_design/' . $name;
        $res = $this->_me->http_request(1, 3, $path, json_encode($data), 1);
        $data = json_decode($res, true);
        if (isset($data['error'])) {
            throw new CouchbaseException($data['reason']);
        }
        return true;
    }

    /**
     * Retrieves a design documents from the bucket.
     *
     * @param string $name Name of the design document.
     * @return mixed
     */
    public function getDesignDocument($name) {
        $path = '_design/' . $name;
        $res = $this->_me->http_request(1, 1, $path, NULL, 2);
        $data = json_decode($res, true);
        if (isset($data['error'])) {
            return false;
        }
        return $data;
    }

    /**
     * Deletes a design document from the bucket.
     *
     * @param string $name Name of the design document.
     * @return mixed
     */
    public function removeDesignDocument($name) {
        $path = '_design/' . $name;
        $res = $this->_me->http_request(1, 4, $path, NULL, 2);
        return json_decode($res, true);
    }

    /**
     * List all N1QL indexes that are registered for the current bucket.
     */
    public function listN1qlIndexes() {
        return $this->_me->n1ix_list();
    }

    /**
     * Create a primary N1QL index.
     *
     * @param string $customName the custom name for the primary index.
     * @param boolean $ignoreIfExist if a primary index already exists, an exception will be thrown unless this is set
     *                               to true.
     * @param boolean $defer true to defer building of the index until buildN1qlDeferredIndexes()}is called (or a direct
     *                       call to the corresponding query service API).
     */
    public function createN1qlPrimaryIndex($customName = '', $ignoreIfExist = false, $defer = false) {
        return $this->_me->n1ix_create($customName, '', '', $ignoreIfExist, $defer, true);
    }

    /**
     * Create a secondary index for the current bucket.
     *
     * @param string $indexName the name of the index.
     * @param array $fields the JSON fields to index.
     * @param string $whereClause the WHERE clause of the index.
     * @param boolean $ignoreIfExist if a secondary index already exists with that name, an exception will be thrown
     *                               unless this is set to true.
     * @param boolean $defer true to defer building of the index until buildN1qlDeferredIndexes() is called (or a direct
     *                       call to the corresponding query service API).
     */
    public function createN1qlIndex($indexName, $fields, $whereClause = '', $ignoreIfExist = false, $defer = false) {
        return $this->_me->n1ix_create($indexName, json_encode($fields), $whereClause, $ignoreIfExist, $defer, false);
    }

    /**
     * Drop the given primary index associated with the current bucket.
     *
     * @param string $customName the custom name of the primary index or empty string for default.
     * @param boolean $ignoreIfNotExist if true, attempting to drop on a bucket without any primary index won't cause an
     *                                  exception to be propagated.
     */
    public function dropN1qlPrimaryIndex($customName = '', $ignoreIfNotExist = false) {
        return $this->_me->n1ix_drop($customName, $ignoreIfNotExist, true);
    }

    /**
     * Drop the given secondary index associated with the current bucket.
     *
     * @param string $indexName the name of the index.
     * @param boolean $ignoreIfNotExist if true, attempting to drop on a bucket without any primary index won't cause an
     *                                  exception to be propagated.
     */
    public function dropN1qlIndex($indexName, $ignoreIfNotExist = false) {
        return $this->_me->n1ix_drop($indexName, $ignoreIfNotExist, false);
    }

    /**
     * Flushes this bucket (clears all data).
     *
     * @return mixed
     */
    public function flush() {
        $path = "/pools/default/buckets/" . $this->_name . "/controller/doFlush";
        $res = $this->_me->http_request(2, 2, $path, NULL, 2);
        return json_decode($res, true);
    }

    /**
     * Retrieves bucket status information
     *
     * Returns an associative array of status information as seen
     * by the cluster for this bucket.  The exact structure of the
     * returned data can be seen in the Couchbase Manual by looking
     * at the bucket /info endpoint.
     *
     * @return mixed The status information.
     */
    public function info() {
        $path = "/pools/default/buckets/" . $this->_name;
        $res = $this->_me->http_request(2, 1, $path, NULL, 2);
        return json_decode($res, true);
    }
}
