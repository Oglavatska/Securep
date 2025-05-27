<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test</title>
</head>
<body>
<?php
$filename= "E:/Lena/Git/Project1/log_files/test.txt";
if ($handle = fopen($filename, "r")) {
    while (($line = fgets($handle)) !== false) {

        // pro Zeile alle wichtige Werte holen:
        $log = htmlspecialchars($line);

        //IP Adresse
        $ip_adress = strtok($log, " ");

        //specs
        $specs_position = strpos($log, "specs=");

        // Wenn das Wort gefunden wurde
        if ($specs_position !== false) {
            // Den String nach dem Wort abschneiden
            $specs = strtok(substr($log, $specs_position + strlen("specs=")), " ");
        }
        if (isset($specs)) {
                $decoded = base64_decode($specs);
                if ($decoded !== false) {
                    $json = @gzdecode($decoded);
                    if ($json !== false) {
                        $specObj = json_decode($json, true);
                        if (is_array($specObj)) {
                            $mac = $specObj['mac'] ?? null;
                            $cpu = $specObj['cpu'] ?? null;
                            echo "mac".$mac."<hr>";
                        }
                    }
                }

        }
        // Datenbank Verbindung:
        $pdo = new PDO("mysql:host=localhost;dbname=db_training", "root", "");
        $serial = 1;
        $sql = "INSERT INTO log_entries (ip_adress, serial, mac, cpu) VALUES (:ip_adress, :serial,:mac, :cpu)";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':ip_adress' => $ip_adress,
            ':serial' => $serial,
            ':mac' => $mac,
            ':cpu' => $cpu
        ]);


    }
    fclose($handle);
} else {
    echo "File $filename existiert nicht!";
}
?>
</body>
</html>