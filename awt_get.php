<?php
$file = 'headers.txt';
$header ="\n===================================================================\nComment: Valid Browser\nExpected Response Code: default_unblock_codes\nExpected Triggered Rule: \nExpected Response: \nUnique-Id: a-".rand()." \nAttack Family: valid traffic from browserstack\nReal Attack: False\nAttack Type: \n===================================================================\n";
$header .= $_SERVER['REQUEST_METHOD']." /index.php?".$_SERVER["QUERY_STRING"]." ".$_SERVER['SERVER_PROTOCOL']."\n";
foreach (getallheaders() as $name => $value) {
	    echo "$name: $value\n";
	        $header .= $name.": ".$value."\n";
	        echo '<br>';
}
$header .= "\n\n===================================================================";
file_put_contents($file, $header, FILE_APPEND | LOCK_EX);
echo "Connecting IP:" .  $_SERVER["REMOTE_ADDR"] . "<br>";
?>
