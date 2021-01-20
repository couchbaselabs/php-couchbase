<?php
/**
 * The following example demonstrates custom transcoders to show have you can
 * encoder specialized kinds of objects, or store data in specialized formats
 * to the server, rather than using the default methods as defined by the SDK.
 *
 * To see a more thorough but complex example of transcoder functions, please
 * see the Couchbase.class.php at the root of the SDK source tree, which
 * contains the default transcoders.
 *
 * NOTE: When using custom transcoders, it is unlikely that the default
 * transcoders will work against the resulting document.  Thus, if you use a
 * custom encoder to store data, you must use the respective decoder for correct
 * behaviour.
 */
use \Couchbase\ClusterOptions;
use \Couchbase\Cluster;
use \Couchbase\UpsertOptions;
use \Couchbase\GetOptions;

/*
 * Create a new Cluster object to represent the connection to our
 * cluster and specify any needed options such as SSL.
 */
$options = new ClusterOptions();
$options->credentials('Administrator', 'password');
$cluster = new Cluster('couchbase://localhost', $options);

/*
 * We open the default bucket to store our cached data in.
 */
$bucket = $cluster->bucket("default");
$collection = $bucket->defaultCollection();

/*
 * Some flags for differentiating what kind of data is stored so our
 * decoder knows what to do with it.
 */
define('CBTE_FLAG_IMG', 1);
define('CBTE_FLAG_JSON', 2);

/*
 * Lets define some custom transcoding functions.  For this example, any
 * image types that are stored will be serialized as a PNG, and all other
 * object types will be encoded as JSON.
 */
function example_encoder($value) {
    if (gettype($value) == 'resource' && get_resource_type($value) == 'gd') {
        // This is am image, lets capture the PNG data!
        ob_start();
        imagepng($value);
        $png_data = ob_get_contents();
        ob_end_clean();

        // Return our bytes and flags
        return array($png_data, CBTE_FLAG_IMG, 0);
    } else {
        // This is an arbitrary type, lets JSON encode it
        $json_data = json_encode($value);

        // Return our bytes and flags
        return array($json_data, CBTE_FLAG_JSON, 0);
    }
}
function example_decoder($bytes, $flags, $datatype) {
    if ($flags == CBTE_FLAG_IMG) {
        // Recreate our image object from the stored data
        return imagecreatefromstring($bytes);
    } else if ($flags == CBTE_FLAG_JSON) {
        // Simply JSON decode
        return json_decode($bytes);
    } else {
        // Ugh oh...
        return NULL;
    }
}

/*
 * Create an image to test with
 */
$im = imagecreatetruecolor(300, 50);
$text_color = imagecolorallocate($im, 233, 14, 91);
imagestring($im, 6, 10, 10,  'Couchbase Rocks!', $text_color);

/*
 * Store it in Couchbase.  This should execute our custom encoder.
 */
$options = new UpsertOptions();
$options->encoder('example_encoder'); // Could be any callable.
$collection->upsert('test_image', $im, $options);

/*
 * Now lets retreive it back, it should still be an image thanks to our
 * custom decoder.
 */
$options = new GetOptions();
$options->decoder('example_decoder'); // Could be any callable.
$image_doc = $collection->get('test_image', $options);

/*
 * Output our retrieved document to the browser with a image/png content-type.
 */
header('Content-Type: image/png');
imagepng($image_doc->content());
