<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test</title>
</head>
<body>
<?php
$pdo = new PDO("mysql:host=localhost;dbname=db_training", "root", "");
$filename = "E:/Lena/Git/Project1/log_files/test.log";

if ($handle = fopen($filename, "r")) {
    while (($line = fgets($handle)) !== false) {

        // pro Zeile alle wichtige Werte holen:
        $log = htmlspecialchars($line);

        //IP Adresse
        $ip_adress = strtok($log, " ") ?: null;

        //Datum/Zeit des Zugriffs
        if (preg_match('/\[(.*?)\]/', $log, $matches)) {
            $access_time = new DateTime($matches[1]);
            $access_time = $access_time->format("Y-m-d H:i:s");
        } else {
            $access_time = null;
        }

        //specs
        $specs_position = strpos($log, "specs=");
        // Wenn das Wort gefunden wurde
        if ($specs_position !== false) {
            // Den String nach dem Wort abschneiden
            $specs = strtok(substr($log, $specs_position + strlen("specs=")), " ");
        }
        // serial
        $serial_positon = strpos($log, "serial=");
        if ($specs_position !== false) {
            // Den String nach dem Wort abschneiden
            $serial = strtok(substr($log, $serial_positon + strlen("serial=")), " ");
        } else {
            $serial = null;
        }
        $mac = null;
        $cpu = null;
        if (isset($specs)) {
            $decoded = base64_decode($specs);
            if ($decoded !== false) {
                $json = @gzdecode($decoded);
                if ($json !== false) {
                    $specObj = json_decode($json, true);
                    if (is_array($specObj)) {
                        $mac = $specObj['mac'] ?? null;
                        $cpu = $specObj['cpu'] ?? null;
                    }
                }
            }
        }
        // Datenbank Verbindung:

        $sql_insert = "INSERT INTO log_entries (ip_adress, serial, mac, cpu, access_time) VALUES (:ip_adress, :serial,:mac, :cpu, :access_time)";
        $stmt = $pdo->prepare($sql_insert);
        $stmt->execute([
            ':ip_adress' => $ip_adress,
            ':serial' => $serial,
            ':mac' => $mac,
            ':cpu' => $cpu,
            ':access_time' => $access_time,
        ]);
    }
    fclose($handle);
} else {
    echo "File $filename existiert nicht!";
}
// get 10 Lizenz-Seriennummern, die am häufigsten versuchen, auf den Server zuzugreifen
$license = $pdo->query("
    SELECT serial, access_time, COUNT(*) AS access_count
    FROM log_entries
    GROUP BY serial
    ORDER BY access_count DESC
    LIMIT 10
");
?>
<!--Tabelle mit Ergebnissen-->
<table style="border: 1px solid #000000;">
    <tr>
        <th style="border: 1px solid #000000; padding: 5px 10px;">Lizens-Seriennummer</th>
        <th style="border: 1px solid #000000; padding: 5px 10px;">Anzhal des Zugriffs</th>
        <th style="border: 1px solid #000000; padding: 5px 10px;">Datum des Zugriffs</th>
    </tr>

    <?php foreach ($license as $row):
        $datum = new DateTime($row['access_time']);
        $datum = $datum->format("Y-m-d");
        ?>
        <tr>
            <td style="border-bottom: 1px solid #000000;  border-left: 1px solid #000000; border-right: 1px solid #000000; padding: 5px 10px;"> <?php echo $row['serial']; ?></td>
            <td style="border-bottom: 1px solid #000000;  border-right: 1px solid #000000; padding: 5px 10px; text-align: center;"> <?php echo $row['access_count']; ?></td>
            <td style="border-bottom: 1px solid #000000;border-right: 1px solid #000000; text-align: center;"> <?php echo $datum; ?></td>
        </tr>
    <?php endforeach; ?>
</body>
</html>