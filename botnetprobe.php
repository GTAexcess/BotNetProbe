<?php
/**
 * BotNetProbe
 * Author: Mohammad Ali
 * Description: Analyzes network logs (CSV) to detect botnet communication patterns like repeated pings to external IPs or abnormal traffic bursts.
 */

if ($argc != 2) {
    echo "Usage: php botnetprobe.php path/to/netlog.csv\n";
    exit(1);
}

$file = $argv[1];
if (!file_exists($file)) {
    echo "[ERROR] Log file not found: $file\n";
    exit(1);
}

$handle = fopen($file, "r");
$headers = fgetcsv($handle);
$connections = [];
$suspicious = [];

echo "📡 Scanning network log: $file\n";

while (($data = fgetcsv($handle)) !== false) {
    list($timestamp, $src_ip, $dst_ip, $port, $protocol) = $data;
    $key = "$src_ip → $dst_ip:$port [$protocol]";
    $connections[$key][] = strtotime($timestamp);
}
fclose($handle);

// Detection: same destination hit repeatedly in short time
foreach ($connections as $conn => $times) {
    sort($times);
    for ($i = 1; $i < count($times); $i++) {
        $diff = $times[$i] - $times[$i - 1];
        if ($diff < 10 && count($times) >= 5) {
            $suspicious[$conn] = count($times);
            break;
        }
    }
}

// Output
if (count($suspicious)) {
    echo "\n🚨 Potential Botnet Behavior Detected:\n";
    foreach ($suspicious as $conn => $count) {
        echo "[ALERT] $conn → $count bursts\n";
    }
} else {
    echo "\n✅ No botnet-like behavior found.\n";
}
?>
