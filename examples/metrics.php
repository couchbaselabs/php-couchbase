<?php

use \Couchbase\Cluster;
use \Couchbase\ClusterOptions;
use \Couchbase\Meter;
use \Couchbase\NoopMeter;
use \Couchbase\LoggingMeter;
use \Couchbase\ValueRecorder;

class MyValueRecorder implements ValueRecorder {
	public function recordValue(int $number): void {
		printf("recording value: $number\n");
	}
}

class MyMeter implements Meter {
	public function valueRecorder(string $name, array $tags = []): ValueRecorder {
		var_dump($name);
		var_dump($tags);
		return new MyValueRecorder();
	}
}

$options = new ClusterOptions();
$options->credentials('Administrator', 'password');

// Custom meter
$options->meter(new MyMeter());

/*
	// Disable metering
	$options->meter(new NoopMeter());
 */

/*
	// Logging meter
	$meter = new LoggingMeter();
	$meter->flushInterval(1000000);
        $options->meter($meter);
 */


$cluster = new Cluster('couchbase://localhost', $options);

$bucket = $cluster->bucket("default");
$collection = $bucket->defaultCollection();

for ($i = 0; $i < 1000; ++$i) {
	$collection->upsert("key-$i", ["val" => "foo-$i"]);
}
