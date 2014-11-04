<?php
/**
 * File for the CouchbaseCluster class.
 *
 * @author Brett Lawson <brett19@gmail.com>
 */

/**
 * Represents a cluster connection.
 *
 * @package Couchbase
 */
class CouchbaseCluster {
    /**
     * @var _CouchbaseCluster
     * @ignore
     *
     * Pointer to a manager instance if there is one.
     */
    private $_manager = NULL;

    /**
     * @var string
     * @ignore
     *
     * A cluster DSN to connect with.
     */
    private $_dsn;

    /**
     * Creates a connection to a cluster.
     *
     * Creates a CouchbaseCluster object and begins the bootstrapping
     * process necessary for communications with the Couchbase Server.
     *
     * @param string $dsn A cluster DSn to connect with.
     * @param string $username The username for the cluster.
     * @param string $password The password for the cluster.
     *
     * @throws CouchbaseException
     */
    public function __construct($dsn = 'http://127.0.0.1/', $username = '', $password = '') {
        $this->_dsn = cbdsn_parse($dsn);
    }

    /**
     * Constructs a connection to a bucket.
     *
     * @param string $name The name of the bucket to open.
     * @param string $password The bucket password to authenticate with.
     * @return CouchbaseBucket A bucket object.
     *
     * @throws CouchbaseException
     *
     * @see CouchbaseBucket CouchbaseBucket
     */
    public function openBucket($name = 'default', $password = '') {
        $bucketDsn = cbdsn_normalize($this->_dsn);
        $bucketDsn['bucket'] = $name;
        $dsnStr = cbdsn_stringify($bucketDsn);
        return new CouchbaseBucket($dsnStr, $name, $password);
    }

    /**
     * Creates a manager allowing the management of a Couchbase cluster.
     *
     * @param $username The administration username.
     * @param $password The administration password.
     * @return CouchbaseClusterManager
     */
    public function manager($username, $password) {
        if (!$this->_manager) {
            $this->_manager = new CouchbaseClusterManager(
                cbdsn_stringify($this->_dsn), $username, $password);
        }
        return $this->_manager;
    }

}
