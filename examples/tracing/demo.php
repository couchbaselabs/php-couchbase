<?php declare(strict_types=1);

/**
 * This example expects cluster running on the localhost with bucket named "default"
 *
 * Build extension (libcouchbase must be installed in the system)
 *
 *     $ bin/build.sh
 *
 * Run the example
 *
 *     $ bin/run.sh examples/tracing/demo.php
 */

/*
 * Make sure log level is high enough to display tracing messages
 */
ini_set("couchbase.log_level", "INFO");

use Couchbase\Cluster;
use Couchbase\ClusterOptions;
use Couchbase\TimeoutException;
use Couchbase\UpsertOptions;

$options = new ClusterOptions();
$options->credentials("Administrator", "password");

/**
 * Allowed options for tracing:
 *
 * |----------------------------------------+----------+---------|
 * | key                                    | type     | default |
 * |----------------------------------------+----------+---------|
 * | enable_tracing                         | bool     |    true |
 * | tracing_orphaned_queue_size            | int      |     128 |
 * | tracing_orphaned_queue_flush_interval  | duration |    10.0 |
 * | tracing_threshold_queue_size           | int      |     128 |
 * | tracing_threshold_queue_flush_interval | duration |    10.0 |
 * | tracing_threshold_kv                   | duration |     0.5 |
 * | tracing_threshold_query                | duration |     1.0 |
 * | tracing_threshold_view                 | duration |     1.0 |
 * | tracing_threshold_search               | duration |     1.0 |
 * | tracing_threshold_analytics            | duration |     1.0 |
 * |----------------------------------------+----------+---------|
 *
 * duration is given in seconds with fractions after floating point
 * (e.g. "2.5" is 2 seconds 500 milliseconds)
 */
$connectionString = "couchbase://127.0.0.1?".
                  "tracing_orphaned_queue_flush_interval=5&". /* every 5 seconds */
                  "tracing_threshold_queue_flush_interval=3&". /* every 3 seconds */
                  "tracing_threshold_kv=0.01"; /* 10 milliseconds */

$cluster = new Cluster($connectionString, $options);
$bucket = $cluster->bucket("default");
$collection = $bucket->defaultCollection();

/*
 * Create new document
 */
$document = ["answer" => 42, "updated_at" => date("r")];
$collection->upsert("foo", $document);

/*
 * Replacing the document with big body and very small deadline should trigger a client-side timeout,
 * in which case server response to be reported as orphan
 */
$options = new UpsertOptions();
$options->timeout(1);
/*
 * Generate document with 10M payload, that should be unfriendly to compressing function
 * and longer to process on the server side
 */
$document = ["noise" => base64_encode(random_bytes(15_000_000))];
$numberOfTimeouts = 0;
while (true) {
    try {
        $collection->upsert("foo", $document, $options);
    } catch (TimeoutException $e) {
        $numberOfTimeouts++;
        if ($numberOfTimeouts > 3) {
            break;
        }
    }
}

/*
 * Messages like one below will appear in the log for the orphaned response
 *
 * [cb,WARN] (tracer L:147 I:2929787644) Orphan responses observed: {"count":2,"service":"kv","top":[{"last_local_address":"127.0.0.1:41210","last_local_id":"aa562ed8aea102fc/a4a9305660272565","last_operation_id":"0x11","last_remote_address":"127.0.0.1:11210","operation_name":"upsert","server_us":0,"total_us":34904},{"last_local_address":"127.0.0.1:41210","last_local_id":"aa562ed8aea102fc/a4a9305660272565","last_operation_id":"0xb","last_remote_address":"127.0.0.1:11210","operation_name":"upsert","server_us":0,"total_us":32195}]}
 */

/*
 * Threshold reports will be written like the following
 *
 * [cb,INFO] (tracer L:149 I:2929787644) Operations over threshold: {"count":14,"service":"kv","top":[{"operation_name":"php/upsert","total_us":537133},{"operation_name":"php/upsert","total_us":513483},{"operation_name":"php/upsert","total_us":510245},{"operation_name":"php/upsert","total_us":500094},{"last_local_address":"127.0.0.1:41210","last_local_id":"aa562ed8aea102fc/a4a9305660272565","last_operation_id":"0x3","last_remote_address":"127.0.0.1:11210","operation_name":"upsert","server_us":150315,"total_us":320528},{"last_local_address":"127.0.0.1:41210","last_local_id":"aa562ed8aea102fc/a4a9305660272565","last_operation_id":"0x2","last_remote_address":"127.0.0.1:11210","operation_name":"upsert","server_us":126118,"total_us":317381},{"last_local_address":"127.0.0.1:41210","last_local_id":"aa562ed8aea102fc/a4a9305660272565","last_operation_id":"0x4","last_remote_address":"127.0.0.1:11210","operation_name":"upsert","server_us":149572,"total_us":311246},{"operation_name":"php/request_encoding","total_us":200289
 */
