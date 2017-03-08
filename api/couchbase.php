<?php
/**
 * INI entries:
 *
 * * `couchbase.log_level` (string), default: `"WARN"`
 *
 *   controls amount of information, the module will send to PHP error log. Accepts the following values in order of
 *   increasing verbosity: `"FATAL"`, `"ERROR"`, `"WARN"`, `"INFO"`, `"DEBUG"`, `"TRACE"`.
 *
 * * `couchbase.encoder.format` (string), default: `"json"`
 *
 *   selects serialization format for default encoder (\Couchbase\defaultEncoder). Accepts the following values:
 *   * `"json"` - encodes objects and arrays as JSON object (using `json_encode()`), primitives written in stringified form,
 *      which is allowed for most of the JSON parsers as valid values. For empty arrays JSON array preferred, if it is
 *      necessary, use `new stdClass()` to persist empty JSON object. Note, that only JSON format considered supported by
 *      all Couchbase SDKs, everything else is private implementation (i.e. `"php"` format won't be readable by .NET SDK).
 *   * `"php"` - uses PHP serialize() method to encode the document.
 *   * `"igbinary"` - uses pecl/igbinary to encode the document in even more efficient than `"php"` format. Might not be
 *      available, if the Couchbase PHP SDK didn't find it during build phase, in this case constant
 *      \Couchbase\HAVE_IGBINARY will be false.
 *
 * * `couchbase.encoder.compression` (string), default: `"none"`
 *
 *   selects compression algorithm. Also see related compression options below. Accepts the following values:
 *   * `"fastlz"` - uses FastLZ algorithm. The module might be configured to use system fastlz library during build,
 *     othewise vendored version will be used. This algorithm is always available.
 *   * `"zlib"` - uses compression implemented by libz. Might not be available, if the system didn't have libz headers
 *     during build phase. In this case \Couchbase\HAVE_ZLIB will be false.
 *   * `"off"` or `"none"` - compression will be disabled, but the library will still read compressed values.
 *
 * * `couchbase.encoder.compression_threshold` (long), default: `0`
 *
 *   controls minimum size of the document value in bytes to use compression. For example, if threshold 100 bytes,
 *   and the document size is 50, compression will be disabled for this particular document.
 *
 * * `couchbase.encoder.compression_factor` (float), default: `0.0`
 *
 *   controls the minimum ratio of the result value and original document value to proceed with persisting compressed
 *   bytes. For example, the original document consists of 100 bytes. In this case factor 1.0 will require compressor
 *   to yield values not larger than 100 bytes (100/1.0), and 1.5 -- not larger than 66 bytes (100/1.5).
 *
 * * `couchbase.decoder.json_arrays` (boolean), default: `false`
 *
 *   controls the form of the documents, returned by the server if they were in JSON format. When true, it will generate
 *   arrays of arrays, otherwise instances of stdClass.
 *
 * @package Couchbase
 */
namespace Couchbase {
    /** If igbinary extension was not found during build phase this constant will store 0 */
    define("Couchbase\\HAVE_IGBINARY", 1);
    /** If libz headers was not found during build phase this constant will store 0 */
    define("Couchbase\\HAVE_ZLIB", 1);

    /** Encodes documents as JSON objects (see INI section for details)
     * @see \Couchbase\basicEncoderV1
     */
    define("Couchbase\\ENCODER_FORMAT_JSON", 0);
    /** Encodes documents using pecl/igbinary encoder (see INI section for details)
     * @see \Couchbase\basicEncoderV1
     */
    define("Couchbase\\ENCODER_FORMAT_IGBINARY", 1);
    /** Encodes documents using PHP serialize() (see INI section for details)
     * @see \Couchbase\basicEncoderV1
     */
    define("Couchbase\\ENCODER_FORMAT_PHP", 2);

    /** Do not use compression for the documents
     * @see \Couchbase\basicEncoderV1
     */
    define("Couchbase\\ENCODER_COMPRESSION_NONE", 0);
    /** Use zlib compressor for the documents
     * @see \Couchbase\basicEncoderV1
     */
    define("Couchbase\\ENCODER_COMPRESSION_ZLIB", 1);
    /** Use FastLZ compressor for the documents
     * @see \Couchbase\basicEncoderV1
     */
    define("Couchbase\\ENCODER_COMPRESSION_FASTLZ", 2);

    /**
     * Compress input using FastLZ algorithm.
     *
     * @param string $data original data
     * @return string compressed binary string
     */
    function fastlzCompress($data) {}

    /**
     * Decompress input using FastLZ algorithm.
     *
     * @param string $data compressed binary string
     * @return string original data
     */
    function fastlzDecompress($data) {}

    /**
     * Compress input using zlib. Raises Exception when extension compiled without zlib support.
     *
     * @see \Couchbase\HAVE_ZLIB
     * @param string $data original data
     * @return string compressed binary string
     */
    function zlibCompress($data) {}

    /**
     * Compress input using zlib. Raises Exception when extension compiled without zlib support.
     *
     * @see \Couchbase\HAVE_ZLIB
     * @param string $data compressed binary string
     * @return string original data
     */
    function zlibDecompress($data) {}

    /**
     * Returns value as it received from the server without any transformations.
     *
     * It is useful for debug purpose to inspect bare value.
     *
     * @param string $bytes
     * @param int $flags
     * @param int $datatype
     * @return string Document as it received from the Couchbase.
     *
     * @example examples/api/couchbase.passthruDecoder.php
     * @see \Couchbase\Bucket::setTranscoder()
     */
    function passthruDecoder($bytes, $flags, $datatype) {}

    /**
     * Returns the value, which has been passed and zero as flags and datatype.
     *
     * It is useful for debug purposes, or when the value known to be a string, otherwise behavior is not defined (most
     * likely it will generate error).
     *
     * @param string $value document to be stored in the Couchbase
     * @return array Array with three values: [bytes, 0, 0]
     *
     * @see \Couchbase\Bucket::setTranscoder()
     */
    function passthruEncoder($value) {}

    /**
     * Decodes value using \Couchbase\basicDecoderV1.
     *
     * It passes `couchbase.decoder.*` INI properties as $options.
     *
     * @param string $bytes Binary string received from the Couchbase, which contains encoded document
     * @param int $flags Flags which describes document encoding
     * @param int $datatype Extra field for datatype (not used at the moment)
     * @return mixed Decoded document object
     *
     * @see \Couchbase\basicDecoderV1
     * @see \Couchbase\Bucket::setTranscoder()
     */
    function defaultDecoder($bytes, $flags, $datatype) {}

    /**
     * Encodes value using \Couchbase\basicDecoderV1.
     *
     * It passes `couchbase.encoder.*` INI properties as $options.
     *
     * @param mixed $value document to be stored in the Couchbase
     * @return array Array with three values: [bytes, flags, datatype]
     *
     * @see \Couchbase\basicDecoderV1
     * @see \Couchbase\Bucket::setTranscoder()
     */
    function defaultEncoder($value) {}

    /**
     * Decodes value according to Common Flags (RFC-20)
     *
     * @param string $bytes Binary string received from the Couchbase, which contains encoded document
     * @param int $flags Flags which describes document encoding
     * @param int $datatype Extra field for datatype (not used at the moment)
     * @param array $options
     * @return mixed Decoded document object
     *
     * @see https://github.com/couchbaselabs/sdk-rfcs RFC-20 at SDK RFCs repository
     */
    function basicDecoderV1($bytes, $flags, $datatype, $options) {}

    /**
     * Encodes value according to Common Flags (RFC-20)
     *
     * @param mixed $value document to be stored in the Couchbase
     * @param array $options Encoder options (see detailed description in INI section)
     *   * "sertype" (default: \Couchbase::ENCODER_FORMAT_JSON) encoding format to use
     *   * "cmprtype" (default: \Couchbase::ENCODER_COMPRESSION_NONE) compression type
     *   * "cmprthresh" (default: 0) compression threshold
     *   * "cmprfactor" (default: 0) compression factor
     * @return array Array with three values: [bytes, flags, datatype]
     *
     * @see https://github.com/couchbaselabs/sdk-rfcs RFC-20 at SDK RFCs repository
     */
    function basicEncoderV1($value, $options) {}

    /**
     * Exception represeting all errors generated by the extension
     */
    class Exception extends \Exception {
    }

    /**
     * Represents Couchbase Document, which stores metadata and the value.
     *
     * The instances of this class returned by K/V commands of the \Couchbase\Bucket
     *
     * @see \Couchbase\Bucket
     */
    class Document {
        /**
         * @var Exception exception object in case of error, or NULL
         */
        public $error;

        /**
         * @var mixed The value stored in the Couchbase.
         */
        public $value;

        /**
         * @var int Flags, describing the encoding of the document on the server side.
         */
        public $flags;

        /**
         * @var string The last known CAS value of the document
         */
        public $cas;

        /**
         * @var MutationToken
         * The optional, opaque mutation token set after a successful mutation.
         *
         * Note that the mutation token is always NULL, unless they are explicitly enabled on the
         * connection string (`?fetch_mutation_tokens=true`), the server version is supported (>= 4.0.0)
         * and the mutation operation succeeded.
         *
         * If set, it can be used for enhanced durability requirements, as well as optimized consistency
         * for N1QL queries.
         */
        public $token;
    }

    /**
     * A fragment of a JSON Document returned by the sub-document API.
     *
     * @see \Couchbase\Bucket::mutateIn()
     * @see \Couchbase\Bucket::lookupIn()
     */
    class DocumentFragment {
        /**
         * @var Exception exception object in case of error, or NULL
         */
        public $error;

        /**
         * @var mixed The value sub-document command returned.
         */
        public $value;

        /**
         * @var string The last known CAS value of the document
         */
        public $cas;

        /**
         * @var MutationToken
         * The optional, opaque mutation token related to updated document the environment.
         *
         * Note that the mutation token is always NULL, unless they are explicitly enabled on the
         * connection string (`?fetch_mutation_tokens=true`), the server version is supported (>= 4.0.0)
         * and the mutation operation succeeded.
         *
         * If set, it can be used for enhanced durability requirements, as well as optimized consistency
         * for N1QL queries.
         */
        public $token;
    }

    /**
     * Represents a Couchbase Server Cluster.
     *
     * It is an entry point to the library, and in charge of opening connections to the Buckets.
     * In addition it can instantiate \Couchbase\ClusterManager to peform cluster-wide operations.
     *
     * @see \Couchbase\Bucket
     * @see \Couchbase\ClusterManager
     * @see \Couchbase\Authenticator
     */
    final class Cluster {
        /**
         * Create cluster object
         *
         * @param string $connstr connection string
         */
        final public function __construct($connstr) {}

        /**
         * Open connection to the Couchbase bucket
         *
         * @param string $name Name of the bucket.
         * @param string $password Password of the bucket to override authenticator.
         * @return Bucket
         *
         * @see \Couchbase\Authenticator
         */
        final public function openBucket($name = "default", $password = "") {}

        /**
         * Open management connection to the Couchbase cluster.
         *
         * @param string $username Name of the administrator to override authenticator or NULL.
         * @param string $password Password of the administrator to override authenticator or NULL.
         * @return ClusterManager
         *
         * @see \Couchbase\Authenticator
         */
        final public function manager($username = null, $password = null) {}

        /**
         * Associate authenticator with Cluster
         *
         * @param Authenticator $authenticator
         * @return null
         *
         * @see \Couchbase\Authenticator
         * @see \Couchbase\ClassicAuthenticator
         */
        final public function authenticate($authenticator) {}
    }

    /**
     * Provides management capabilities for a Couchbase Server Cluster
     *
     * @see \Couchbase\Cluster
     */
    final class ClusterManager {
        /** @ignore */
        final private function __construct() {}

        /**
         * Lists all buckets on this cluster.
         *
         * @return array
         */
        final public function listBuckets() {}

        /**
         * Creates new bucket
         *
         * @param string $name Name of the bucket
         * @param array $options Bucket options
         *   * "authType" (default: "sasl") type of the bucket authentication
         *   * "bucketType" (default: "couchbase") type of the bucket
         *   * "ramQuotaMB" (default: 100) memory quota of the bucket
         *   * "replicaNumber" (default: 1) number of replicas.
         *
         * @see https://developer.couchbase.com/documentation/server/current/rest-api/rest-bucket-create.html
         *   More options and details
         */
        final public function createBucket($name, $options = []) {}

        /**
         * Removes a bucket identified by its name.
         *
         * @param string $name name of the bucket
         *
         * @see https://developer.couchbase.com/documentation/server/current/rest-api/rest-bucket-delete.html
         *   More details
         */
        final public function removeBucket($name) {}

        /**
         * Provides information about the cluster.
         *
         * Returns an associative array of status information as seen on the cluster.  The exact structure of the returned
         * data can be seen in the Couchbase Manual by looking at the cluster /info endpoint.
         *
         * @return array
         *
         * @see https://developer.couchbase.com/documentation/server/current/rest-api/rest-cluster-get.html
         *   Retrieving Cluster Information
         */
        final public function info() {}
    }

    /**
     * Represents connection to the Couchbase Server
     *
     * @property int $operationTimeout
     *   The operation timeout is the maximum amount of time the library will wait
     *   for an operation to receive a response before invoking its callback with
     *   a failure status.
     *
     *   An operation may timeout if:
     *
     *   * A server is taking too long to respond
     *   * An updated cluster configuration has not been promptly received
     *
     * @property int $viewTimeout
     *   The I/O timeout for HTTP requests to Couchbase Views API
     *
     * @property int $n1qlTimeout
     *   The I/O timeout for N1QL queries.
     *
     * @property int $httpTimeout
     *   The I/O timeout for HTTP queries (management API).
     *
     * @property int $configTimeout
     *   How long the client will wait to obtain the initial configuration.
     *
     * @property int $configNodeTimeout
     *   Per-node configuration timeout.
     *
     *   This timeout sets the amount of time to wait for each node within
     *   the bootstrap/configuration process. This interval is a subset of
     *   the $configTimeout option mentioned above and is intended to ensure
     *   that the bootstrap process does not wait too long for a given node.
     *   Nodes that are physically offline may never respond and it may take
     *   a long time until they are detected as being offline.
     *
     * @property int $configDelay
     *   Config refresh throttling
     *
     *   Modify the amount of time (in microseconds) before the configiration
     *   error threshold will forcefully be set to its maximum number forcing
     *   a configuration refresh.
     *
     *   Note that if you expect a high number of timeouts in your operations,
     *   you should set this to a high number. If you are using the default
     *   timeout setting, then this value is likely optimal.
     *
     * @property int $htconfigIdleTimeout
     *   Idling/Persistence for HTTP bootstrap
     *
     *   By default the behavior of the library for HTTP bootstrap is to keep
     *   the stream open at all times (opening a new stream on a different host
     *   if the existing one is broken) in order to proactively receive
     *   configuration updates.
     *
     *   The default value for this setting is -1. Changing this to another
     *   number invokes the following semantics:
     *
     *   * The configuration stream is not kept alive indefinitely. It is kept
     *     open for the number of seconds specified in this setting. The socket
     *     is closed after a period of inactivity (indicated by this setting).
     *
     *   * If the stream is broken (and no current refresh was requested by
     *     the client) then a new stream is not opened.
     *
     * @property int $durabilityInterval
     *   The time the client will wait between repeated probes to a given server.
     *
     * @property int $durabilityTimeout
     *   The time the client will spend sending repeated probes to a given key's
     *   vBucket masters and replicas before they are deemed not to have satisfied
     *   the durability requirements
     *
     * @see https://developer.couchbase.com/documentation/server/current/sdk/php/start-using-sdk.html
     *   Start Using SDK
     */
    final class Bucket {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @param string $name
         * @return int
         */
        final private function __get($name) {}

        /**
         * @ignore
         * @param string $name
         * @param int $value
         * @return int
         */
        final private function __set($name, $value) {}

        /**
         * Returns an instance of a CouchbaseBucketManager for performing management operations against a bucket.
         *
         * @return BucketManager
         */
        final public function manager() {}

        /**
         * Sets custom encoder and decoder functions for handling serialization.
         *
         * @param callable $encoder
         * @param callable $decoder
         *
         * @example examples/api/couchbase.passthruDecoder.php
         * @see \Couchbase\defaultEncoder
         * @see \Couchbase\defaultDecoder
         * @see \Couchbase\passthruEncoder
         * @see \Couchbase\passthruDecoder
         */
        final public function setTranscoder($encoder, $decoder) {}

        /**
         * Retrieves a document
         *
         * @param string|array $ids one or more IDs
         * @param array $options options
         *   * "lockTime" non zero if the documents have to be locked
         *   * "expiry" non zero if the expiration time should be updated
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see \Couchbase\Bucket::getAndLock()
         * @see \Couchbase\Bucket::getAndTouch()
         * @see \Couchbase\Bucket::unlock()
         * @see \Couchbase\Bucket::touch()
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function get($ids, $options = []) {}

        /**
         * Retrieves a document and locks it.
         *
         * After the document has been locked on the server, its CAS would be masked,
         * and all mutations of it will be rejected until the server unlocks the document
         * automatically or it will be done manually with \Couchbase\Bucket::unlock() operation.
         *
         * @param string|array $ids one or more IDs
         * @param int $lockTime time to lock the documents
         * @param array $options options
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see \Couchbase\Bucket::unlock()
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         * @see https://forums.couchbase.com/t/is-there-a-way-to-do-pessimistic-locking-for-more-than-30-seconds/10666/3
         *   Forum post about getting server defaults for the $lockTime
         */
        final public function getAndLock($ids, $lockTime, $options = []) {}

        /**
         * Retrieves a document and updates its expiration time.
         *
         * @param string|array $ids one or more IDs
         * @param int $expiry time after which the document will not be accessible.
         *      If larger than 30 days (60*60*24*30), it will be interpreted by the
         *      server as absolute UNIX time (seconds from epoch 1970-01-01T00:00:00).
         * @param array $options options
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function getAndTouch($ids, $expiry, $options = []) {}

        /**
         * Retrieves a document from a replica.
         *
         * @param string|array $ids one or more IDs
         * @param array $options options
         *   * "index" the replica index. If the index is zero, it will return
         *      first successful replica, otherwise it will read only selected node.
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/failure-considerations.html
         *  More about failure considerations.
         */
        final public function getFromReplica($ids, $options = []) {}

        /**
         * Inserts or updates a document, depending on whether the document already exists on the cluster.
         *
         * @param string|array $ids one or more IDs
         * @param mixed $value value of the document
         * @param array $options options
         *   * "expiry" document expiration time in seconds. If larger than 30 days (60*60*24*30),
         *      it will be interpreted by the server as absolute UNIX time (seconds from epoch
         *      1970-01-01T00:00:00).
         *   * "persist_to" how many nodes the key should be persisted to (including master).
         *      If set to 0 then persistence will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which persistence
         *      is possible (which will always contain at least the master node).
         *   * "replicate_to" how many nodes the key should be persisted to (excluding master).
         *      If set to 0 then replication will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which replication
         *      is possible (which may be 0 if the bucket is not configured for replicas).
         *   * "flags" override flags (not recommended to use)
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function upsert($ids, $value, $options = []) {}

        /**
         * Inserts a document. This operation will fail if the document already exists on the cluster.
         *
         * @param string|array $ids one or more IDs
         * @param mixed $value value of the document
         * @param array $options options
         *   * "expiry" document expiration time in seconds. If larger than 30 days (60*60*24*30),
         *      it will be interpreted by the server as absolute UNIX time (seconds from epoch
         *      1970-01-01T00:00:00).
         *   * "persist_to" how many nodes the key should be persisted to (including master).
         *      If set to 0 then persistence will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which persistence
         *      is possible (which will always contain at least the master node).
         *   * "replicate_to" how many nodes the key should be persisted to (excluding master).
         *      If set to 0 then replication will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which replication
         *      is possible (which may be 0 if the bucket is not configured for replicas).
         *   * "flags" override flags (not recommended to use)
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function insert($ids, $value, $options = []) {}

        /**
         * Replaces a document. This operation will fail if the document does not exists on the cluster.
         *
         * @param string|array $ids one or more IDs
         * @param mixed $value value of the document
         * @param array $options options
         *   * "cas" last known document CAS, which serves for optimistic locking.
         *   * "expiry" document expiration time in seconds. If larger than 30 days (60*60*24*30),
         *      it will be interpreted by the server as absolute UNIX time (seconds from epoch
         *      1970-01-01T00:00:00).
         *   * "persist_to" how many nodes the key should be persisted to (including master).
         *      If set to 0 then persistence will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which persistence
         *      is possible (which will always contain at least the master node).
         *   * "replicate_to" how many nodes the key should be persisted to (excluding master).
         *      If set to 0 then replication will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which replication
         *      is possible (which may be 0 if the bucket is not configured for replicas).
         *   * "flags" override flags (not recommended to use)
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function replace($ids, $value, $options = []) {}

        /**
         * Appends content to a document.
         *
         * On the server side it just contatenate passed value to the existing one.
         * Note that this might make the value un-decodable. Consider sub-document API
         * for partial updates of the JSON documents.
         *
         * @param string|array $ids one or more IDs
         * @param mixed $value value of the document
         * @param array $options options
         *   * "cas" last known document CAS, which serves for optimistic locking.
         *   * "expiry" document expiration time in seconds. If larger than 30 days (60*60*24*30),
         *      it will be interpreted by the server as absolute UNIX time (seconds from epoch
         *      1970-01-01T00:00:00).
         *   * "persist_to" how many nodes the key should be persisted to (including master).
         *      If set to 0 then persistence will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which persistence
         *      is possible (which will always contain at least the master node).
         *   * "replicate_to" how many nodes the key should be persisted to (excluding master).
         *      If set to 0 then replication will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which replication
         *      is possible (which may be 0 if the bucket is not configured for replicas).
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see \Couchbase\Bucket::mutateIn()
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function append($ids, $value, $options = []) {}

        /**
         * Prepends content to a document.
         *
         * On the server side it just contatenate existing value to the passed one.
         * Note that this might make the value un-decodable. Consider sub-document API
         * for partial updates of the JSON documents.
         *
         * @param string|array $ids one or more IDs
         * @param mixed $value value of the document
         * @param array $options options
         *   * "cas" last known document CAS, which serves for optimistic locking.
         *   * "expiry" document expiration time in seconds. If larger than 30 days (60*60*24*30),
         *      it will be interpreted by the server as absolute UNIX time (seconds from epoch
         *      1970-01-01T00:00:00).
         *   * "persist_to" how many nodes the key should be persisted to (including master).
         *      If set to 0 then persistence will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which persistence
         *      is possible (which will always contain at least the master node).
         *   * "replicate_to" how many nodes the key should be persisted to (excluding master).
         *      If set to 0 then replication will not be checked. If set to a negative
         *      number, will be set to the maximum number of nodes to which replication
         *      is possible (which may be 0 if the bucket is not configured for replicas).
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see \Couchbase\Bucket::mutateIn()
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function prepend($ids, $value, $options = []) {}

        /**
         * Removes the document.
         *
         * @param string|array $ids one or more IDs
         * @param array $options options
         *   * "cas" last known document CAS, which serves for optimistic locking.
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function remove($ids, $options = []) {}

        /**
         * Updates document's expiration time.
         *
         * @param string|array $ids one or more IDs
         * @param int $expiry time after which the document will not be accessible.
         *      If larger than 30 days (60*60*24*30), it will be interpreted by the
         *      server as absolute UNIX time (seconds from epoch 1970-01-01T00:00:00).
         * @param array $options options
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function touch($ids, $expiry, $options = []) {}

        /**
         * Increments or decrements a key (based on $delta)
         *
         * @param string|array $ids one or more IDs
         * @param int $delta the number whih determines the sign (positive/negative) and the value of the increment
         * @param array $options options
         *   * "initial" initial value of the counter if it does not exist
         *   * "expiry" time after which the document will not be accessible.
         *      If larger than 30 days (60*60*24*30), it will be interpreted by the
         *      server as absolute UNIX time (seconds from epoch 1970-01-01T00:00:00).
         *   * "groupid" override value for hashing (not recommended to use)
         * @return \Couchbase\Document|array document or list of the documents
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/core-operations.html
         *   Overview of K/V operations
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/document-operations.html
         *   More details about K/V operations for PHP SDK
         */
        final public function counter($ids, $delta = 1, $options = []) {}

        /**
         * Returns a builder for reading subdocument API.
         *
         * @param string $id The ID of the JSON document
         * @return LookupInBuilder
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function lookupIn($id) {}

        /**
         * Retrieves specified paths in JSON document
         *
         * This is essentially a shortcut for `lookupIn($id)->get($paths)->execute()`.
         *
         * @param string $id The ID of the JSON document
         * @param string ...$paths List of the paths inside JSON documents (see "Path syntax" section of the
         *   "Sub-Document Operations" documentation).
         * @return \Couchbase\DocumentFragment
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function retrieveIn($id, ...$paths) {}

        /**
         * Returns a builder for writing subdocument API.
         *
         * @param string $id The ID of the JSON document
         * @param string $cas Last known document CAS value for optimisti locking
         * @return MutateInBuilder
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function mutateIn($id, $cas) {}

        /**
         * Performs a query to Couchbase Server
         *
         * @param N1qlQuery|ViewQuery|SpatialViewQuery|SearchQuery $query
         * @param bool $jsonAsArray if true, the values in the result rows (or hits) will be represented as
         *    PHP arrays, otherwise they will be instances of the `stdClass`
         * @return object Query-specific result object.
         *
         * @see \Couchbase\N1qlQuery
         * @see \Couchbase\SearchQuery
         * @see \Couchbase\ViewQuery
         * @see \Couchbase\SpatialViewQuery
         */
        final public function query($query, $jsonAsArray = false) {}

        /**
         * Returns size of the map
         *
         * @param string $id ID of the document
         * @return int number of the key-value pairs
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function mapSize($id) {}

        /**
         * Add key to the map
         *
         * @param string $id ID of the document
         * @param string $key key
         * @param mixed $value value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function mapAdd($id, $key, $value) {}

        /**
         * Removes key from the map
         *
         * @param string $id ID of the document
         * @param string $key key
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function mapRemove($id, $key) {}

        /**
         * Get an item from a map
         *
         * @param string $id ID of the document
         * @param string $key key
         * @return mixed value associated with the key
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function mapGet($id, $key) {}

        /**
         * Returns size of the set
         *
         * @param string $id ID of the document
         * @return int number of the elements
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function setSize($id) {}

        /**
         * Add value to the set
         *
         * Note, that currently only primitive values could be stored in the set (strings, integers and booleans).
         *
         * @param string $id ID of the document
         * @param string|int|float|bool $value new value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function setAdd($id, $value) {}

        /**
         * Check if the value exists in the set
         *
         * @param string $id ID of the document
         * @param string|int|float|bool $value value to check
         * @return bool true if the value exists in the set
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function setExists($id, $value) {}

        /**
         * Remove value from the set
         *
         * @param string $id ID of the document
         * @param string|int|float|bool $value value to remove
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function setRemove($id, $value) {}

        /**
         * Returns size of the list
         *
         * @param string $id ID of the document
         * @return int number of the elements
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function listSize($id) {}

        /**
         * Add an element to the end of the list
         *
         * @param string $id ID of the document
         * @param mixed $value new value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function listPush($id, $value) {}

        /**
         * Add an element to the beginning of the list
         *
         * @param string $id ID of the document
         * @param mixed $value new value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function listShift($id, $value) {}

        /**
         * Remove an element at the given position
         *
         * @param string $id ID of the document
         * @param int $index index of the element to be removed
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function listRemove($id, $index) {}

        /**
         * Get an element at the given position
         *
         * @param string $id ID of the document
         * @param int $index index of the element
         * @return mixed the value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function listGet($id, $index) {}

        /**
         * Set an element at the given position
         *
         * @param string $id ID of the document
         * @param int $index index of the element
         * @param mixed $value new value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function listSet($id, $index, $value) {}

        /**
         * Check if the list contains specified value
         *
         * @param string $id ID of the document
         * @param mixed $value value to look for
         * @reuturn bool true if the list contains the value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function listExists($id, $value) {}

        /**
         * Returns size of the queue
         *
         * @param string $id ID of the document
         * @return int number of the elements in the queue
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function queueSize($id) {}

        /**
         * Checks if the queue contains specified value
         *
         * @param string $id ID of the document
         * @param mixed $value value to look for
         * @return bool true if the queue contains the value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function queueExists($id, $value) {}

        /**
         * Add an element to the beginning of the queue
         *
         * @param string $id ID of the document
         * @param mixed $value new value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function queueAdd($id, $value) {}

        /**
         * Remove the element at the end of the queue and return it
         *
         * @param string $id ID of the document
         * @return mixed removed value
         *
         * @see https://developer.couchbase.com/documentation/server/current/sdk/php/datastructures.html
         *   More details on Data Structures
         * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
         *   Overview of Sub-Document Operations
         */
        final public function queueRemove($id) {}
    }

    /**
     * Provides management capabilities for the Couchbase Bucket
     */
    final class BucketManager {
        /** @ignore */
        final private function __construct() {}

        /**
         * Returns information about the bucket
         *
         * Returns an associative array of status information as seen by the cluster for
         * this bucket. The exact structure of the returned data can be seen in the Couchbase
         * Manual by looking at the bucket /info endpoint.
         *
         * @return array
         *
         * @see https://developer.couchbase.com/documentation/server/current/rest-api/rest-bucket-info.html
         *   Getting Single Bucket Information
         */
        final public function info() {}

        /**
         * Flushes the bucket (clears all data)
         */
        final public function flush() {}

        /**
         * Returns all design documents of the bucket.
         *
         * @return array
         */
        final public function listDesignDocuments() {}

        /**
         * Get design document by its name
         *
         * @param string $name name of the design document (without _design/ prefix)
         * @return array
         */
        final public function getDesignDocument($name) {}

        /**
         * Removes design document by its name
         *
         * @param string $name name of the design document (without _design/ prefix)
         */
        final public function removeDesignDocument($name) {}

        /**
         * Creates or replaces design document.
         *
         * @param string $name name of the design document (without _design/ prefix)
         * @param array $document
         */
        final public function upsertDesignDocument($name, $document) {}

        /**
         * Inserts design document and fails if it is exist already.
         *
         * @param string $name name of the design document (without _design/ prefix)
         * @param array $document
         */
        final public function insertDesignDocument($name, $document) {}

        /**
         * List all N1QL indexes that are registered for the current bucket.
         *
         * @return array
         */
        final public function listN1qlIndexes() {}

        /**
         * Create a primary N1QL index.
         *
         * @param string $customName the custom name for the primary index.
         * @param bool $ignoreIfExist if a primary index already exists, an exception
         *   will be thrown unless this is set to true.
         * @param bool $defer true to defer index building.
         */
        final public function createN1qlPrimaryIndex($customName = '', $ignoreIfExist = false, $defer = false) {}

        /**
         * Create secondary N1QL index.
         *
         * @param string $name name of the index
         * @param array $fields list of JSON fields to index
         * @param string $whereClause the WHERE clause of the index.
         * @param bool $ignoreIfExist if a secondary index already exists, an exception
         *   will be thrown unless this is set to true.
         * @param bool $defer true to defer index building.
         */
        final public function createN1qlIndex($name, $fields, $whereClause = '', $ignoreIfExist = false, $defer = false) {}

        /**
         * Drop the given primary index
         *
         * @param string $customName the custom name for the primary index
         * @param bool $ignoreIfNotExist if a primary index does not exist, an exception
         *   will be thrown unless this is set to true.
         */
        final public function dropN1qlPrimaryIndex($customName = '', $ignoreIfNotExist = false) {}

        /**
         * Drop the given secondary index
         *
         * @param string $name the index name
         * @param bool $ignoreIfNotExist if a secondary index does not exist, an exception
         *   will be thrown unless this is set to true.
         */
        final public function dropN1qlIndex($name, $ignoreIfNotExist = false) {}
    }

    /**
     * Interface of authentication containers.
     *
     * @see \Couchbase\Cluster::authenticate()
     * @see \Couchbase\ClassicAuthenticator
     */
    interface Authenticator {}

    /**
     * Authenticator based on login/password credentials.
     *
     * This authenticator uses separate credentials for Cluster management interface
     * as well as for each bucket.
     *
     * @example examples/api/couchbase.Authenticator.php Cluster authentication
     *
     * @example examples/api/couchbase.N1qlQuery.crossBucket.php Cross-bucket N1QL query
     *
     * @see \Couchbase\Cluster::authenticate()
     * @see \Couchbase\Authenticator
     */
    final class ClassicAuthenticator implements Authenticator {
        /**
         * Registers cluster management credentials in the container
         *
         * @param string $username admin username
         * @param string $password admin password
         */
        final public function cluster($username, $password) {}

        /**
         * Registers bucket credentials in the container
         *
         * @param string $name bucket name
         * @param string $password bucket password
         */
        final public function bucket($name, $password) {}
    }

    /**
     * An object which contains meta information of the document needed to enforce query consistency.
     */
    final class MutationToken {
        /** @ignore */
        final private function __construct() {}

        /**
         * Creates new mutation token
         *
         * @param string $bucketName name of the bucket
         * @param int $vbucketId partition number
         * @param string $vbucketUuid UUID of the partition
         * @param string $sequenceNumber sequence number inside partition
         */
        final public static function from($bucketName, $vbucketId, $vbucketUuid, $sequenceNumber) {}

        /**
         * Returns bucket name
         *
         * @return string
         */
        final public function bucketName() {}

        /**
         * Returns partition number
         *
         * @return int
         */
        final public function vbucketId() {}

        /**
         * Returns UUID of the partition
         *
         * @return string
         */
        final public function vbucketUuid() {}

        /**
         * Returns the sequence number inside partition
         *
         * @return string
         */
        final public function sequenceNumber() {}
    }

    /**
     * Container for mutation tokens.
     */
    final class MutationState {
        /** @ignore */
        final private function __construct() {}

        /**
         * Create container from the given mutation token holders.
         *
         * @param array|Document|DocumentFragment $source anything that can have attached MutationToken
         * @return MutationState
         *
         * @see \Couchbase\MutationToken
         */
        final public static function from($source) {}

        /**
         * Update container with the given mutation token holders.
         *
         * @param array|Document|DocumentFragment $source anything that can have attached MutationToken
         *
         * @see \Couchbase\MutationToken
         */
        final public function add($source) {}
    }

    /**
     * Common interface for all View queries
     *
     * @see \Couchbase\ViewQuery
     * @see \Couchbase\SpatialViewQuery
     */
    interface ViewQueryEncodable {
        /**
         * Returns associative array, representing the View query.
         *
         * @return array object which is ready to be serialized.
         */
        function encode();
    }

    /**
     * Represents regular Couchbase Map/Reduce View query
     *
     * @see \Couchbase\Bucket::query()
     * @see \Couchbase\SpatialViewQuery
     * @see https://developer.couchbase.com/documentation/server/current/sdk/php/view-queries-with-sdk.html
     *   MapReduce Views
     * @see https://developer.couchbase.com/documentation/server/current/architecture/querying-data-with-views.html
     *   Quering Data with Views
     * @see https://developer.couchbase.com/documentation/server/current/rest-api/rest-views-get.html
     *   Getting Views Information
     */
    final class ViewQuery implements ViewQueryEncodable {
        /** Force a view update before returning data */
        const UPDATE_BEFORE = 1;
        /** Allow stale views */
        const UPDATE_NONE = 2;
        /** Allow stale view, update view after it has been accessed. */
        const UPDATE_AFTER = 3;

        const ORDER_ASCENDING = 1;
        const ORDER_DESCENDING = 2;

        /** @ignore */
        final private function __construct() {}

        /**
         * Creates a new Couchbase ViewQuery instance for performing a view query.
         *
         * @param string $designDocumentName the name of the design document to query
         * @param string $viewName the name of the view to query
         * @return ViewQuery
         */
        final public static function from($designDocumentName, $viewName) {}

        /**
         * Creates a new Couchbase ViewQuery instance for performing a spatial query.
         * @param string $designDocumentName the name of the design document to query
         * @param string $viewName the name of the view to query
         * @return SpatialViewQuery
         */
        final public static function fromSpatial($designDocumentName, $viewName) {}

        /**
         * Returns associative array, representing the View query.
         *
         * @return array object which is ready to be serialized.
         */
        function encode() {}

        /**
         * Limits the result set to a specified number rows.
         *
         * @param int $limit maximum number of records in the response
         * @return ViewQuery
         */
        final public function limit($limit) {}

        /**
         * Skips a number o records rom the beginning of the result set
         *
         * @param int $skip number of records to skip
         * @return ViewQuery
         */
        final public function skip($skip) {}

        /**
         * Specifies the mode of updating to perorm before and after executing the query
         *
         * @param int $consistency use constants UPDATE_BEFORE, UPDATE_NONE, UPDATE_AFTER
         * @return ViewQuery
         *
         * @see \Couchbase\ViewQuery::UPDATE_BEFORE
         * @see \Couchbase\ViewQuery::UPDATE_NONE
         * @see \Couchbase\ViewQuery::UPDATE_AFTER
         */
        final public function consistency($consistency) {}

        /**
         * Orders the results by key as specified
         *
         * @param int $order use contstants ORDER_ASCENDING, ORDER_DESCENDING
         * @return ViewQuery
         */
        final public function order($order) {}

        /**
         * Specifies whether the reduction function should be applied to results of the query.
         *
         * @param bool $reduce
         * @return ViewQuery
         */
        final public function reduce($reduce) {}

        /**
         * Group the results using the reduce function to a group or single row.
         *
         * Important: this setter and groupLevel should not be used together in the
         * same ViewQuery. It is sufficient to only set the grouping level only and
         * use this setter in cases where you always want the highest group level
         * implictly.
         *
         * @param bool $group
         * @return ViewQuery
         *
         * @see \Couchbase\ViewQuery#groupLevel
         */
        final public function group($group) {}

        /**
         * Specify the group level to be used.
         *
         * Important: group() and this setter should not be used together in the
         * same ViewQuery. It is sufficient to only use this setter and use group()
         * in cases where you always want the highest group level implictly.
         *
         * @param int $groupLevel the number of elements in the keys to use
         * @return ViewQuery
         *
         * @see \Couchbase\ViewQuery#group
         */
        final public function groupLevel($groupLevel) {}

        /**
         * Restict results of the query to the specified key
         *
         * @param mixed $key key
         * @return ViewQuery
         */
        final public function key($key) {}

        /**
         * Restict results of the query to the specified set of keys
         *
         * @param array $keys set of keys
         * @return ViewQuery
         */
        final public function keys($keys) {}

        /**
         * Specifies a range of the keys to return from the index.
         *
         * @param mixed $startKey
         * @param mixed $endKey
         * @param bool $inclusiveEnd
         * @return ViewQuery
         */
        final public function range($startKey, $endKey, $inclusiveEnd = false) {}

        /**
         * Specifies start and end document IDs in addition to range limits.
         *
         * This might be needed for more precise pagination with a lot of documents
         * with the same key selected into the same page.
         *
         * @param string $startKeyDocumentId document ID
         * @param string $endKeyDocumentId document ID
         * @return ViewQuery
         */
        final public function idRange($startKeyDocumentId, $endKeyDocumentId) {}

        /**
         * Specifies custom options to pass to the server.
         *
         * Note that these options are expected to be already encoded.
         *
         * @param array $customParameters parameters
         * @return ViewQuery
         *
         * @see https://developer.couchbase.com/documentation/server/current/rest-api/rest-views-get.html
         *   Getting Views Information
         */
        final public function custom($customParameters) {}
    }

    /**
     * Represents spatial Couchbase Map/Reduce View query
     *
     * @see \Couchbase\Bucket::query()
     * @see \Couchbase\ViewQuery
     * @see https://developer.couchbase.com/documentation/server/current/architecture/querying-geo-data-spatial-views.html
     *   Querying Geographic Data with Spatial Views
     * @see https://developer.couchbase.com/documentation/server/current/rest-api/rest-views-get.html
     *   Getting Views Information
     * @see https://developer.couchbase.com/documentation/server/current/views/sv-query-parameters.html
     *   Querying spatial views
     */
    final class SpatialViewQuery implements ViewQueryEncodable {
        /** @ignore */
        final private function __construct() {}

        /**
         * Returns associative array, representing the View query.
         *
         * @return array object which is ready to be serialized.
         */
        function encode() {}

        /**
         * Limits the result set to a specified number rows.
         *
         * @param int $limit maximum number of records in the response
         * @return SpatialViewQuery
         */
        final public function limit($limit) {}

        /**
         * Skips a number o records rom the beginning of the result set
         *
         * @param int $skip number of records to skip
         * @return SpatialViewQuery
         */
        final public function skip($skip) {}

        /**
         * Specifies the mode of updating to perorm before and after executing the query
         *
         * @param int $consistency use constants UPDATE_BEFORE, UPDATE_NONE, UPDATE_AFTER
         * @return SpatialViewQuery
         *
         * @see \Couchbase\ViewQuery::UPDATE_BEFORE
         * @see \Couchbase\ViewQuery::UPDATE_NONE
         * @see \Couchbase\ViewQuery::UPDATE_AFTER
         */
        final public function consistency($consistency) {}

        /**
         * Orders the results by key as specified
         *
         * @param int $order use contstants ORDER_ASCENDING, ORDER_DESCENDING
         * @return SpatialViewQuery
         */
        final public function order($order) {}

        /**
         * Specifies the bounding box to search within.
         *
         * Note, using bbox() is discouraged, startRange/endRange is more flexible and should be preferred.
         *
         * @param array $bbox bounding box coordinates expressed as a list of numeric values
         * @return SpatialViewQuery
         *
         * @see \Couchbase\SpatialViewQuery#startRange()
         * @see \Couchbase\SpatialViewQuery#endRange()
         */
        final public function bbox($bbox) {}

        /**
         * Specify start range for query
         *
         * @param array $range
         * @return SpatialViewQuery
         *
         * @see https://developer.couchbase.com/documentation/server/current/views/sv-query-parameters.html
         *   Querying spatial views
         */
        final public function startRange($range) {}

        /**
         * Specify end range for query
         *
         * @param array $range
         * @return SpatialViewQuery
         *
         * @see https://developer.couchbase.com/documentation/server/current/views/sv-query-parameters.html
         *   Querying spatial views
         */
        final public function endRange($range) {}

        /**
         * Specifies custom options to pass to the server.
         *
         * Note that these options are expected to be already encoded.
         *
         * @param array $customParameters parameters
         *
         * @see https://developer.couchbase.com/documentation/server/current/rest-api/rest-views-get.html
         *   Getting Views Information
         * @see https://developer.couchbase.com/documentation/server/current/views/sv-query-parameters.html
         *   Querying spatial views
         */
        final public function custom($customParameters) {}
    }

    /**
     * Represents a N1QL query
     *
     * @see https://developer.couchbase.com/documentation/server/current/sdk/n1ql-query.html
     *   Querying with N1QL
     * @see https://developer.couchbase.com/documentation/server/current/sdk/php/n1ql-queries-with-sdk.html
     *   N1QL from the SDKs
     * @see https://developer.couchbase.com/documentation/server/current/n1ql/n1ql-rest-api/index.html
     *   N1QL REST API
     * @see https://developer.couchbase.com/documentation/server/current/performance/index-scans.html
     *   Understanding Index Scans
     * @see https://developer.couchbase.com/documentation/server/current/performance/indexing-and-query-perf.html
     *   Indexing JSON Documents and Query Performance
     */
    final class N1qlQuery {
        /**
         * This is the default (for single-statement requests).
         * No timestamp vector is used in the index scan.
         * This is also the fastest mode, because we avoid the cost of obtaining the vector,
         * and we also avoid any wait for the index to catch up to the vector.
         */
        const NOT_BOUNDED = 1;
        /**
         * This implements strong consistency per request.
         * Before processing the request, a current vector is obtained.
         * The vector is used as a lower bound for the statements in the request.
         * If there are DML statements in the request, RYOW is also applied within the request.
         */
        const REQUEST_PLUS = 2;
        /**
         * This implements strong consistency per statement.
         * Before processing each statement, a current vector is obtained
         * and used as a lower bound for that statement.
         */
        const STATEMENT_PLUS = 3;

        /** @ignore */
        final private function __construct() {}

        /**
         * Creates new N1qlQuery instance directly from the N1QL string.
         *
         * @param string $statement N1QL string
         * @return N1qlQuery
         */
        final public static function fromString($statement) {}

        /**
         * Allows to specify if this query is adhoc or not.
         *
         * If it is not adhoc (so performed often), the client will try to perform optimizations
         * transparently based on the server capabilities, like preparing the statement and
         * then executing a query plan instead of the raw query.
         *
         * @param bool $adhoc if query is adhoc, default is true (plain execution)
         * @return N1qlQuery
         */
        final public function adhoc($adhoc) {}

        /**
         * Allows to pull credentials from the Authenticator
         *
         * @param bool $crossBucket if query includes joins for multiple buckets (default is false)
         * @return N1qlQuery
         *
         * @example examples/api/couchbase.N1qlQuery.crossBucket.php Cross-bucket N1QL query
         *
         * @see \Couchbase\Authenticator
         * @see \Couchbase\ClassicAuthenticator
         */
        final public function crossBucket($crossBucket) {}

        /**
         * Specify array of positional parameters
         *
         * Previously specified positional parameters will be replaced.
         * Note: carefully choose type of quotes for the query string, because PHP also uses `$`
         * (dollar sign) for variable interpolation. If you are using double quotes, make sure
         * that N1QL parameters properly escaped.
         *
         * @param array $params
         * @return N1qlQuery
         *
         * @example examples/api/couchbase.N1qlQuery.positionalParams.php
         */
        final public function positionalParams($params) {}

        /**
         * Specify associative array of named parameters
         *
         * The supplied array of key/value pairs will be merged with already existing named parameters.
         * Note: carefully choose type of quotes for the query string, because PHP also uses `$`
         * (dollar sign) for variable interpolation. If you are using double quotes, make sure
         * that N1QL parameters properly escaped.
         *
         * @param array $params
         * @return N1qlQuery
         *
         * @example examples/api/couchbase.N1qlQuery.namedParams.php
         */
        final public function namedParams($params) {}

        /**
         * Specifies the consistency level for this query
         *
         * @param int $consistency consistency level
         * @return N1qlQuery
         *
         * @see \Couchbase\N1qlQuery::NOT_BOUNDED
         * @see \Couchbase\N1qlQuery::REQUEST_PLUS
         * @see \Couchbase\N1qlQuery::STATEMENT_PLUS
         * @see \Couchbase\N1qlQuery::consistentWith()
         */
        final public function consistency($consistency) {}

        /**
         * Sets mutation state the query should be consistent with
         *
         * @param MutationState $state the container of mutation tokens
         * @return N1qlQuery
         *
         * @see \Couchbase\MutationState
         *
         * @example examples/api/couchbase.N1qlQuery.consistentWith.php
         */
        final public function consistentWith($state) {}
    }

    /**
     * Represents N1QL index definition
     *
     * @see https://developer.couchbase.com/documentation/server/current/performance/indexing-and-query-perf.html
     *   Indexing JSON Documents and Query Performance
     */
    final class N1qlIndex {
        const UNSPECIFIED = 0;
        const GSI = 1;
        const VIEW = 2;

        /** @ignore */
        final private function __construct() {}

        /**
         * Name of the index
         *
         * @var string
         */
        public $name;

        /**
         * Is it primary index
         *
         * @var boolean
         */
        public $isPrimary;

        /**
         * Type of the index
         *
         * @var int
         *
         * @see \Couchbase\N1qlIndex::UNSPECIFIED
         * @see \Couchbase\N1qlIndex::GSI
         * @see \Couchbase\N1qlIndex::VIEW
         */
        public $type;

        /**
         * The descriptive state of the index
         *
         * @var string
         */
        public $state;

        /**
         * The keyspace for the index, typically the bucket name
         * @var string
         */
        public $keyspace;

        /**
         * The namespace for the index. A namespace is a resource pool that contains multiple keyspaces
         * @var string
         */
        public $namespace;

        /**
         * The fields covered by index
         * @var array
         */
        public $fields;

        /**
         * Return the string representation of the index's condition (the WHERE clause
         * of the index), or an empty String if no condition was set.
         *
         * Note that the query service can present the condition in a slightly different
         * manner from when you declared the index: for instance it will wrap expressions
         * with parentheses and show the fields in an escaped format (surrounded by backticks).
         *
         * @var string
         */
        public $condition;
    }

    /**
     * A builder for subdocument lookups. In order to perform the final set of operations, use the
     * execute() method.
     *
     * Instances of this builder should be obtained through \Couchbase\Bucket->lookupIn()
     *
     * @see \Couchbase\Bucket::lookupIn
     * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
     *   Sub-Document Operations
     */
    final class LookupInBuilder {
        /** @ignore */
        final private function __construct() {}

        /**
         * Get a value inside the JSON document.
         *
         * @param string $path the path inside the document where to get the value from.
         * @return LookupInBuilder
         */
        final public function get($path) {}

        /**
         * Check if a value exists inside the document.
         *
         * This doesn't transmit the value on the wire if it exists, saving the corresponding byte overhead.
         *
         * @param string $path the path inside the document to check for existence
         * @return LookupInBuilder
         */
        final public function exists($path) {}

        /**
         * Perform several lookup operations inside a single existing JSON document, using a specific timeout
         * @return DocumentFragment
         *
         * @example examples/api/couchbase.LookupInBuilder.execute.php
         */
        final public function execute() {}
    }

    /**
     * A builder for subdocument mutations. In order to perform the final set of operations, use the
     * execute() method.
     *
     * Instances of this builder should be obtained through \Couchbase\Bucket->mutateIn()
     *
     * @see \Couchbase\Bucket::mutateIn
     * @see https://developer.couchbase.com/documentation/server/current/sdk/subdocument-operations.html
     *   Sub-Document Operations
     */
    final class MutateInBuilder {
        /** @ignore */
        final private function __construct() {}

        /**
         * Insert a fragment provided the last element of the path doesn't exists.
         *
         * @param string $path the path where to insert a new dictionary value.
         * @param mixed $value the new dictionary value to insert.
         * @param bool $createParents true to create missing intermediary nodes
         * @return MutateInBuilder
         */
        final public function insert($path, $value, $createParents = false) {}

        /**
         * Insert a fragment, replacing the old value if the path exists
         *
         * @param string $path the path where to insert (or replace) a dictionary value
         * @param mixed $value the new dictionary value to be applied.
         * @param bool $createParents true to create missing intermediary nodes
         * @return MutateInBuilder
         */
        final public function upsert($path, $value, $createParents = false) {}

        /**
         * Replace an existing value by the given fragment
         *
         * @param string $path the path where the value to replace is
         * @param mixed $value the new value
         * @return MutateInBuilder
         */
        final public function replace($path, $value) {}

        /**
         * Remove an entry in a JSON document.
         *
         * Scalar, array element, dictionary entry, whole array or dictionary, depending on the path.
         *
         * @param string $path the path to remove
         * @return MutateInBuilder
         */
        final public function remove($path) {}

        /**
         * Prepend to an existing array, pushing the value to the front/first position in the array.
         *
         * @param string $path the path of the array
         * @param mixed $value the value to insert at the front of the array
         * @param bool $createParents true to create missing intermediary nodes
         * @return MutateInBuilder
         */
        final public function arrayPrepend($path, $value, $createParents = false) {}

        /**
         * Prepend multiple values at once in an existing array.
         *
         * Push all values in the collection's iteration order to the front/start of the array.
         * For example given an array [A, B, C], prepending the values X and Y yields [X, Y, A, B, C]
         * and not [[X, Y], A, B, C].
         *
         * @param string $path the path of the array
         * @param array $values the values to insert at the front of the array as individual elements
         * @param bool $createParents true to create missing intermediary nodes
         * @return MutateInBuilder
         */
        final public function arrayPrependAll($path, $values, $createParents = false) {}

        /**
         * Append to an existing array, pushing the value to the back/last position in the array.
         *
         * @param string $path the path of the array
         * @param mixed $value the value to insert at the back of the array
         * @param bool $createParents true to create missing intermediary nodes
         * @return MutateInBuilder
         */
        final public function arrayAppend($path, $value, $createParents = false) {}

        /**
         * Append multiple values at once in an existing array.
         *
         * Push all values in the collection's iteration order to the back/end of the array.
         * For example given an array [A, B, C], appending the values X and Y yields [A, B, C, X, Y]
         * and not [A, B, C, [X, Y]].
         *
         * @param string $path the path of the array
         * @param array $values the values to individually insert at the back of the array
         * @param bool $createParents true to create missing intermediary nodes
         * @return MutateInBuilder
         */
        final public function arrayAppendAll($path, $values, $createParents = false) {}

        /**
         * Insert into an existing array at a specific position
         *
         * Position denoted in the path, eg. "sub.array[2]".
         *
         * @param string $path the path (including array position) where to insert the value
         * @param mixed $value the value to insert in the array
         * @return MutateInBuilder
         */
        final public function arrayInsert($path, $value) {}

        /**
         * Insert multiple values at once in an existing array at a specified position.
         *
         * Position denoted in the path, eg. "sub.array[2]"), inserting all values in the collection's iteration order
         * at the given position and shifting existing values beyond the position by the number of elements in the
         * collection.
         *
         * For example given an array [A, B, C], inserting the values X and Y at position 1 yields [A, B, X, Y, C]
         * and not [A, B, [X, Y], C].

         * @param string $path the path of the array
         * @param array $values the values to insert at the specified position of the array, each value becoming
         *   an entry at or after the insert position.
         * @return MutateInBuilder
         */
        final public function arrayInsertAll($path, $values) {}

        /**
         * Insert a value in an existing array only if the value
         * isn't already contained in the array (by way of string comparison).
         *
         * @param string $path the path to mutate in the JSON
         * @param mixed $value the value to insert
         * @param bool $createParents true to create missing intermediary nodes
         * @return MutateInBuilder
         */
        final public function arrayAddUnique($path, $value, $createParents = false) {}

        /**
         * Increment/decrement a numerical fragment in a JSON document.
         *
         * If the value (last element of the path) doesn't exist the counter
         * is created and takes the value of the delta.
         *
         * @param string $path the path to the counter (must be containing a number).
         * @param int $delta the value to increment or decrement the counter by
         * @param bool $createParents true to create missing intermediary nodes
         * @return MutateInBuilder
         */
        final public function counter($path, $delta, $createParents = false) {}

        /**
         * Perform several mutation operations inside a single existing JSON document.
         * @return DocumentFragment
         *
         * @example examples/api/couchbase.MutateInBuilder.execute.php
         */
        final public function execute() {}
    }

    /**
     * Represents full text search query
     *
     * @see https://developer.couchbase.com/documentation/server/4.6/sdk/php/full-text-searching-with-sdk.html
     *   Searching from the SDK
     */
    final class SearchQuery implements \JsonSerializable {
        const HIGHLIGHT_HTML = 'html';
        const HIGHLIGHT_ANSI = 'ansi';
        const HIGHLIGHT_SIMPLE = 'simple';

        /**
         * Prepare boolean search query
         *
         * @return BooleanSearchQuery
         */
        final public static function boolean() {}

        /**
         * Prepare date range search query
         *
         * @return DateRangeSearchQuery
         */
        final public static function dateRange() {}

        /**
         * Prepare boolean field search query
         *
         * @param bool $value
         * @return BooleanFieldSearchQuery
         */
        final public static function booleanField($value) {}

        /**
         * Prepare compound conjunction search query
         *
         * @param SearchQueryPart ...$queries list of inner query parts
         * @return ConjunctionSearchQuery
         */
        final public static function conjuncts(...$queries) {}

        /**
         * Prepare compound disjunction search query
         *
         * @param SearchQueryPart ...$queries list of inner query parts
         * @return DisjunctionSearchQuery
         */
        final public static function disjuncts(...$queries) {}

        /**
         * Prepare document ID search query
         *
         * @param string ...$documentIds
         * @return DocIdSearchQuery
         */
        final public static function docId(...$documentIds) {}

        /**
         * Prepare match search query
         *
         * @param string $match
         * @return MatchSearchQuery
         */
        final public static function match($match) {}

        /**
         * Prepare match all search query
         *
         * @return MatchAllSearchQuery
         */
        final public static function matchAll() {}

        /**
         * Prepare match non search query
         *
         * @return MatchNoneSearchQuery
         */
        final public static function matchNone() {}

        /**
         * Prepare phrase search query
         *
         * @param string ...$terms
         * @return MatchPhraseSearchQuery
         */
        final public static function matchPhrase(...$terms) {}

        /**
         * Prepare prefix search query
         *
         * @param string $prefix
         * @return PrefixSearchQuery
         */
        final public static function prefix($prefix) {}

        /**
         * Prepare query string search query
         *
         * @param string $queryString
         * @return QueryStringSearchQuery
         */
        final public static function queryString($queryString) {}

        /**
         * Prepare regexp search query
         *
         * @param string $regexp
         * @return RegexpSearchQuery
         */
        final public static function regexp($regexp) {}

        /**
         * Prepare term search query
         *
         * @param string $term
         * @return TermSearchQuery
         */
        final public static function term($term) {}

        /**
         * Prepare wildcard search query
         *
         * @param string $wildcard
         * @return WildcardSearchQuery
         */
        final public static function wildcard($wildcard) {}

        /**
         * Prepare term search facet
         *
         * @param string $field
         * @param int $limit
         * @return TermSearchFacet
         */
        final public static function termFacet($field, $limit) {}

        /**
         * Prepare date range search facet
         *
         * @param string $field
         * @param int $limit
         * @return DateRangeSearchFacet
         */
        final public static function dateRangeFacet($field, $limit) {}

        /**
         * Prepare numeric range search facet
         *
         * @param string $field
         * @param int $limit
         * @return NumericRangeSearchFacet
         */
        final public static function numericRangeFacet($field, $limit) {}

        /**
         * Prepare an FTS SearchQuery on an index.
         *
         * Top level query parameters can be set after that by using the fluent API.
         *
         * @param string $indexName the FTS index to search in
         * @param SearchQueryPart $queryPart the body of the FTS query (e.g. a match phrase query)
         */
        final public function __construct($indexName, $queryPart) {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * Add a limit to the query on the number of hits it can return
         *
         * @param int $limit the maximum number of hits to return
         * @return SearchQuery
         */
        final public function limit($limit) {}

        /**
         * Set the number of hits to skip (eg. for pagination).
         *
         * @param int $skip the number of results to skip
         * @return SearchQuery
         */
        final public function skip($skip) {}

        /**
         * Activates the explanation of each result hit in the response
         *
         * @param bool $explain
         * @return SearchQuery
         */
        final public function explain($explain) {}

        /**
         * Sets the server side timeout in milliseconds
         *
         * @param int $serverSideTimeout the server side timeout to apply
         * @return SearchQuery
         */
        final public function serverSideTimeout($serverSideTimeout) {}

        /**
         * Sets the consistency to consider for this FTS query to AT_PLUS and
         * uses the MutationState to parameterize the consistency.
         *
         * This replaces any consistency tuning previously set.
         *
         * @param MutationState $state the mutation state information to work with
         * @return SearchQuery
         */
        final public function consistentWith($state) {}

        /**
         * Configures the list of fields for which the whole value should be included in the response.
         *
         * If empty, no field values are included. This drives the inclusion of the fields in each hit.
         * Note that to be highlighted, the fields must be stored in the FTS index.
         *
         * @param string ...$fields
         * @return SearchQuery
         */
        final public function fields(...$fields) {}

        /**
         * Configures the highlighting of matches in the response
         *
         * @param string $style highlight style to apply. Use constants HIGHLIGHT_HTML,
         *   HIGHLIGHT_ANSI, HIGHLIGHT_SIMPLE.
         * @param string ...$fields the optional fields on which to highlight.
         *   If none, all fields where there is a match are highlighted.
         * @return SearchQuery
         *
         * @see \Couchbase\SearchQuery::HIGHLIGHT_HTML
         * @see \Couchbase\SearchQuery::HIGHLIGHT_ANSI
         * @see \Couchbase\SearchQuery::HIGHLIGHT_SIMPLE
         */
        final public function highlight($style, ...$fields) {}

        /**
         * Adds one SearchFacet to the query
         *
         * This is an additive operation (the given facets are added to any facet previously requested),
         * but if an existing facet has the same name it will be replaced.
         *
         * Note that to be faceted, a field's value must be stored in the FTS index.
         *
         * @param string $name
         * @param SearchFacet $facet
         * @return SearchQuery
         *
         * @see \Couchbase\SearchFacet
         * @see \Couchbase\TermSearchFacet
         * @see \Couchbase\NumericRangeSearchFacet
         * @see \Couchbase\DateRangeSearchFacet
         */
        final public function addFacet($name, $facet) {}
    }

    /**
     * Common interface for all classes, which could be used as a body of SearchQuery
     *
     * @see \Couchbase\SearchQuery::__construct()
     */
    interface SearchQueryPart {}

    /**
     * A FTS query that queries fields explicitly indexed as boolean.
     */
    final class BooleanFieldSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return BooleanFieldSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return BooleanFieldSearchQuery
         */
        final public function field($field) {}
    }

    /**
     * A compound FTS query that allows various combinations of sub-queries.
     */
    final class BooleanSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return BooleanSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param SearchQueryPart ...$queries
         * @return BooleanSearchQuery
         */
        final public function must(...$queries) {}

        /**
         * @param SearchQueryPart ...$queries
         * @return BooleanSearchQuery
         */
        final public function mustNot(...$queries) {}

        /**
         * @param SearchQueryPart ...$queries
         * @return BooleanSearchQuery
         */
        final public function should(...$queries) {}
    }

    /**
     * A compound FTS query that performs a logical AND between all its sub-queries (conjunction).
     */
    final class ConjunctionSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return ConjunctionSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param SearchQueryPart ...$queries
         * @return ConjunctionSearchQuery
         */
        final public function every(...$queries) {}
    }


    /**
     * A compound FTS query that performs a logical OR between all its sub-queries (disjunction). It requires that a
     * minimum of the queries match. The minimum is configurable (default 1).
     */
    final class DisjunctionSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return DisjunctionSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param SearchQueryPart ...$queries
         * @return DisjunctionSearchQuery
         */
        final public function either(...$queries) {}

        /**
         * @param int $min
         * @return DisjunctionSearchQuery
         */
        final public function min($min) {}

    }

    /**
     * A FTS query that matches documents on a range of values. At least one bound is required, and the
     * inclusiveness of each bound can be configured.
     */
    final class DateRangeSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return DateRangeSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return DateRangeSearchQuery
         */
        final public function field($field) {}

        /**
         * @param int|string $start The strings will be taken verbatim and supposed to be formatted with custom date
         *      time formatter (see dateTimeParser). Integers interpreted as unix timestamps and represented as RFC3339
         *      strings.
         * @param bool $inclusive
         * @return DateRangeSearchQuery
         */
        final public function start($start, $inclusive = true) {}

        /**
         * @param int|string $end The strings will be taken verbatim and supposed to be formatted with custom date
         *      time formatter (see dateTimeParser). Integers interpreted as unix timestamps and represented as RFC3339
         *      strings.
         * @param bool $inclusive
         * @return DateRangeSearchQuery
         */
        final public function end($end, $inclusive = false) {}

        /**
         * @param string $dateTimeParser
         * @return DateRangeSearchQuery
         */
        final public function dateTimeParser($dateTimeParser) {}
    }

    /**
     * A FTS query that matches documents on a range of values. At least one bound is required, and the
     * inclusiveness of each bound can be configured.
     */
    final class NumericRangeSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return NumericRangeSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return NumericRangeSearchQuery
         */
        final public function field($field) {}

        /**
         * @param float $min
         * @param bool $inclusive
         * @return NumericRangeSearchQuery
         */
        final public function min($min, $inclusive = true) {}

        /**
         * @param float $max
         * @param bool $inclusive
         * @return NumericRangeSearchQuery
         */
        final public function max($max, $inclusive = false) {}
    }

    /**
     * A FTS query that matches on Couchbase document IDs. Useful to restrict the search space to a list of keys (by using
     * this in a compound query).
     */
    final class DocIdSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return DocIdSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return DocIdSearchQuery
         */
        final public function field($field) {}

        /**
         * @param string ...$documentIds
         * @return DocIdSearchQuery
         */
        final public function docIds(...$documentIds) {}
    }

    /**
     * A FTS query that matches all indexed documents (usually for debugging purposes).
     */
    final class MatchAllSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return MatchAllSearchQuery
         */
        final public function boost($boost) {}
    }

    /**
     * A FTS query that matches 0 document (usually for debugging purposes).
     */
    final class MatchNoneSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return MatchNoneSearchQuery
         */
        final public function boost($boost) {}
    }

    /**
     * A FTS query that matches several given terms (a "phrase"), applying further processing
     * like analyzers to them.
     */
    final class MatchPhraseSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return MatchPhraseSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return MatchPhraseSearchQuery
         */
        final public function field($field) {}

        /**
         * @param string $analyzer
         * @return MatchPhraseSearchQuery
         */
        final public function analyzer($analyzer) {}
    }

    /**
     * A FTS query that matches a given term, applying further processing to it
     * like analyzers, stemming and even #fuzziness(int).
     */
    final class MatchSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return MatchSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return MatchSearchQuery
         */
        final public function field($field) {}

        /**
         * @param string $analyzer
         * @return MatchSearchQuery
         */
        final public function analyzer($analyzer) {}

        /**
         * @param int $prefixLength
         * @return MatchSearchQuery
         */
        final public function prefixLength($prefixLength) {}

        /**
         * @param int $fuzziness
         * @return MatchSearchQuery
         */
        final public function fuzziness($fuzziness) {}
    }

    /**
     * A FTS query that matches several terms (a "phrase") as is. The order of the terms mater and no further processing is
     * applied to them, so they must appear in the index exactly as provided.  Usually for debugging purposes, prefer
     * MatchPhraseQuery.
     */
    final class PhraseSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return PhraseSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return PhraseSearchQuery
         */
        final public function field($field) {}
    }

    /**
     * A FTS query that allows for simple matching of regular expressions.
     */
    final class RegexpSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return RegexpSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return RegexpSearchQuery
         */
        final public function field($field) {}
    }

    /**
     * A FTS query that allows for simple matching using wildcard characters (* and ?).
     */
    final class WildcardSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return WildcardSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return WildcardSearchQuery
         */
        final public function field($field) {}
    }

    /**
     * A FTS query that allows for simple matching on a given prefix.
     */
    final class PrefixSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return PrefixSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return PrefixSearchQuery
         */
        final public function field($field) {}
    }

    /**
     * A FTS query that performs a search according to the "string query" syntax.
     */
    final class QueryStringSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return QueryStringSearchQuery
         */
        final public function boost($boost) {}
    }

    /**
     * A facet that gives the number of occurrences of the most recurring terms in all hits.
     */
    final class TermSearchQuery implements \JsonSerializable, SearchQueryPart {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param float $boost
         * @return TermSearchQuery
         */
        final public function boost($boost) {}

        /**
         * @param string $field
         * @return TermSearchQuery
         */
        final public function field($field) {}

        /**
         * @param int $prefixLength
         * @return TermSearchQuery
         */
        final public function prefixLength($prefixLength) {}

        /**
         * @param int $fuzziness
         * @return TermSearchQuery
         */
        final public function fuzziness($fuzziness) {}
    }

    /**
     * Common interface for all search facets
     *
     * @see \Couchbase\SearchQuery::addFacet()
     * @see \Couchbase\TermSearchFacet
     * @see \Couchbase\DateRangeSearchFacet
     * @see \Couchbase\NumericRangeSearchFacet
     */
    interface SearchFacet {}

    /**
     * A facet that gives the number of occurrences of the most recurring terms in all hits.
     */
    final class TermSearchFacet implements \JsonSerializable, SearchFacet {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}
    }

    /**
     * A facet that categorizes hits inside date ranges (or buckets) provided by the user.
     */
    final class DateRangeSearchFacet implements \JsonSerializable, SearchFacet {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param string $name
         * @param int|string $start
         * @param int|string $end
         * @return DateSearchFacet
         */
        final public function addRange($name, $start, $end) {}
    }

    /**
     * A facet that categorizes hits into numerical ranges (or buckets) provided by the user.
     */
    final class NumericRangeSearchFacet implements \JsonSerializable, SearchFacet {
        /** @ignore */
        final private function __construct() {}

        /**
         * @ignore
         * @return array
         */
        final public function jsonSerialize() {}

        /**
         * @param string $name
         * @param float $min
         * @param float $max
         * @return NumericSearchFacet
         */
        final public function addRange($name, $min, $max) {}
    }
}
