<?php
/**
 * File for the CouchbaseViewQuery class.
 */

/**
 * Represents a view query to be executed against a Couchbase bucket.
 *
 * @package Couchbase
 */
class CouchbaseViewQuery {
    /**
     * @var string
     * @internal
     */
    public $ddoc = '';

    /**
     * @var string
     * @internal
     */
    public $name = '';

    /**
     * @var array
     * @internal
     */
    public $options = array();

    const UPDATE_BEFORE = 1;
    const UPDATE_NONE = 2;
    const UPDATE_AFTER = 3;

    const ORDER_ASCENDING = 1;
    const ORDER_DESCENDING = 2;

    /**
     * @internal
     */
    private function __construct() {
    }

    /**
     * Creates a new Couchbase ViewQuery instance for performing a view query.
     *
     * @param $ddoc The name of the design document to query.
     * @param $name The name of the view to query.
     * @return _CouchbaseDefaultViewQuery
     */
    static public function from($ddoc, $name) {
        $res = new _CouchbaseDefaultViewQuery();
        $res->ddoc = $ddoc;
        $res->name = $name;
        return $res;
    }

    /**
     * Creates a new Couchbase ViewQuery instance for performing a spatial query.
     *
     * @param $ddoc The name of the design document to query.
     * @param $name The name of the view to query.
     * @return _CouchbaseSpatialViewQuery
     */
    static public function fromSpatial($ddoc, $name) {
        $res = new _CouchbaseSpatialViewQuery();
        $res->ddoc = $ddoc;
        $res->name = $name;
        return $res;
    }

    /**
     * Specifies the mode of updating to perform before and after executing
     * this query.
     *
     * @param $stale
     * @return $this
     * @throws CouchbaseException
     */
    public function stale($stale) {
        if ($stale == self::UPDATE_BEFORE) {
            $this->options['stale'] = 'false';
        } else if ($stale == self::UPDATE_NONE) {
            $this->options['stale'] = 'ok';
        } else if ($stale == self::UPDATE_AFTER) {
            $this->options['stale'] = 'update_after';
        } else {
            throw new CouchbaseException('invalid option passed.');
        }
        return $this;
    }

    /**
     * Skips a number of records from the beginning of the result set.
     *
     * @param $skip
     * @return $this
     */
    public function skip($skip) {
        $this->options['skip'] = '' . $skip;
        return $this;
    }

    /**
     * Limits the result set to a restricted number of results.
     *
     * @param $limit
     * @return $this
     */
    public function limit($limit) {
        $this->options['limit'] = '' . $limit;
        return $this;
    }

    /**
     * Specifies custom options to pass to the server.  Note that these
     * options are expected to be already encoded.
     *
     * @param $opts
     * @return $this
     */
    public function custom($opts) {
        foreach ($opts as $k => $v) {
            $this->options[$k] = $v;
        }
        return $this;
    }

    /**
     * Generates the view query as it will be passed to the server.
     *
     * @return string
     * @internal
     */
    public function _toString($type) {
        $path = '/_design/' . $this->ddoc . '/' . $type . '/' . $this->name;
        $args = array();
        foreach ($this->options as $option => $value) {
            array_push($args, $option . '=' . $value);
        }
        $path .= '?' . implode('&', $args);
        return $path;
    }
};

/**
 * Represents a regular view query to perform against the server.  Note that
 * this object should never be instantiated directly, but instead through
 * the CouchbaseViewQuery::from method.
 *
 * @package Couchbase
 */
class _CouchbaseDefaultViewQuery extends CouchbaseViewQuery {

    /**
     * @internal
     */
    public function __construct() {
    }

    /**
     * Orders the results by key as specified.
     *
     * @param $order
     * @return $this
     * @throws CouchbaseException
     */
    public function order($order) {
        if ($order == self::ORDER_ASCENDING) {
            $this->options['descending'] = 'false';
        } else if ($order == self::ORDER_DESCENDING) {
            $this->options['descending'] = 'true';
        } else {
            throw new CouchbaseException('invalid option passed.');
        }
        return $this;
    }

    /**
     * Specifies a reduction function to apply to the index.
     *
     * @param $reduce
     * @return $this
     */
    public function reduce($reduce) {
        if ($reduce) {
            $this->options['reduce'] = 'true';
        } else {
            $this->options['reduce'] = 'false';
        }
        return $this;
    }

    /**
     * Specifies the level of grouping to use on the results.
     *
     * @param $group_level
     * @return $this
     */
    public function group($group_level) {
        if ($group_level >= 0) {
            unset($this->options['group']);
            $this->options['group_level'] = '' . $group_level;
        } else {
            $this->options['group'] = 'true';
            unset($this->options['group_level']);
        }
        return $this;
    }

    /**
     * Specifies a specific key to return from the index.
     *
     * @param $key
     * @return $this
     */
    public function key($key) {
        $this->options['key'] = 
            str_replace('\\\\', '\\', json_encode($key));
        return $this;
    }

    /**
     * Specifies a list of keys to return from the index.
     *
     * @param $keys
     * @return $this
     */
    public function keys($keys) {
        $this->options['keys'] =
            str_replace('\\\\', '\\', json_encode($keys));
        return $this;
    }

    /**
     * Specifies a range of keys to return from the index.
     *
     * @param mixed $start
     * @param mixed $end
     * @param bool $inclusive_end
     * @return $this
     */
    public function range($start = NULL, $end = NULL, $inclusive_end = false) {
        if ($start !== NULL) {
            $this->options['startkey'] =
                str_replace('\\\\', '\\', json_encode($start));
        } else {
            unset($this->options['startkey']);
        }
        if ($end !== NULL) {
            $this->options['endkey'] =
                str_replace('\\\\', '\\', json_encode($end));
        } else {
            unset($this->options['endkey']);
        }
        $this->options['inclusive_end'] = $inclusive_end ? 'true' : 'false';
        return $this;
    }

    /**
     * Specifies a range of document ids to return from the index.
     *
     * @param null $start
     * @param null $end
     * @return $this
     */
    public function id_range($start = NULL, $end = NULL) {
        if ($start !== NULL) {
            $this->options['startkey_docid'] =
                str_replace('\\\\', '\\', json_encode($start));
        } else {
            $this->options['startkey_docid'] = '';
        }
        if ($end !== NULL) {
            $this->options['endkey_docid'] =
                str_replace('\\\\', '\\', json_encode($end));
        } else {
            $this->options['endkey_docid'] = '';
        }
        return $this;
    }

    /**
     * Generates the view query as it will be passed to the server.
     *
     * @return string
     */
    public function toString() {
        return $this->_toString('_view');
    }
};

/**
 * Represents a spatial view query to perform against the server.  Note that
 * this object should never be instantiated directly, but instead through
 * the CouchbaseViewQuery::fromSpatial method.
 *
 * @package Couchbase
 */
class _CouchbaseSpatialViewQuery extends CouchbaseViewQuery {

    /**
     * @internal
     */
    public function __construct() {
    }

    /**
     * Specifies the bounding box to search within.
     *
     * @param number[] $bbox
     * @return $this
     */
    public function bbox($bbox) {
        $this->options['bbox'] = implode(',', $bbox);
        return $this;
    }

    /**
     * Generates the view query as it will be passed to the server.
     *
     * @return string
     */
    public function toString() {
        return $this->_toString('_spatial');
    }
};
