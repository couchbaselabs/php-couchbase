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
