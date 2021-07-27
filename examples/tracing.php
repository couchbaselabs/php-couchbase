<?php

use \Couchbase\Cluster;
use \Couchbase\ClusterOptions;
use \Couchbase\UpsertOptions;
use \Couchbase\RequestSpan;
use \Couchbase\RequestTracer;
use \Couchbase\NoopTracer;
use \Couchbase\ThresholdLoggingTracer;
use \Couchbase\TimeoutException;

class MyRequestSpan implements RequestSpan {
	public function addTag(string $key, $value): void {
		printf("add tag to span: $key => $value\n");
	}

	public function end(): void {
		printf("end span\n");
	}
}

class MyRequestTracer implements RequestTracer {
	public function requestSpan(string $name, RequestSpan $parent = null): RequestSpan {
		printf("request span with name \"$name\"\n");
		return new MyRequestSpan();
	}
}

$options = new ClusterOptions();
$options->credentials('Administrator', 'password');

/*
	// Custom meter
	$options->tracer(new MyRequestTracer());
 */

/*
	// Disable tracing
	$options->tracer(new NoopTracer());
 */

	// Threshold logging tracer
	$tracer = new ThresholdLoggingTracer();
	$tracer->emitInterval(100);
	$tracer->kvThreshold(10);
        $options->tracer($tracer);


$cluster = new Cluster('couchbase://localhost', $options);

$bucket = $cluster->bucket("default");
$collection = $bucket->defaultCollection();

$options = new UpsertOptions();
$options->timeout(50);

$timeouts = 0;
while (true) {
    try {
        $collection->upsert("foo", ["val" => 42], $options);
    } catch (TimeoutException $e) {
        $timeouts++;
        if ($timeouts > 3) {
            break;
        }
    }
}
