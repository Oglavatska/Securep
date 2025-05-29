<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log-Analysator</title>
    <style>
        body {
            font-size: 18px;
        }

        .status {
            position: absolute;
            top: 111px;
            left: 228px;
            font-size: 18px;
        }

        .button-wrapper.import {
            position: relative;
        }

        .buttons {
            padding: 10px 15px;
            font-size: 18px;
            margin: 20px;
        }

        .results {
            margin: 20px;
        }
        table {
            margin-bottom: 20px;
        }
        h3 {
            margin-top: 20px;
        }
        .results_wraper {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

    </style>
</head>

<body>
<?php
// DatenBank verbindung
$pdo = new PDO("mysql:host=localhost;dbname=db_training", "root", "");

$filename = "E:/Lena/Git/Project1/log_files/updatev12-access-pseudonymized.log";
// Um grosse Datei in der DB in kleineren Blcken überzutragen:
$lines_per_run = 2000;
function save_log_file($pdo, $filename, $lines_per_run)
{
    session_start();
    //Fortschritt aus Session holen
    $last_position = $_SESSION['logfile_position'] ?? 0;
    $line_count = $_SESSION['logfile_line'] ?? 0;

    // Datei im Lesemodus öffnen:
    $handle = fopen($filename, "r");
    // an letzte bekannte Stelle springen
    fseek($handle, $last_position);

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $processed = 0;
    if ($handle) {
            $pdo->exec("TRUNCATE TABLE log_entries");
            while (!feof($handle) && $processed < $lines_per_run) {
                $line = fgets($handle);
                if ($line === false) {
                    break;
                }
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
                if ($serial_positon !== false) {
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
                // Datenbank Insert
                $sql_insert = "INSERT INTO log_entries (ip_adress, serial, mac, cpu, access_time) VALUES (:ip_adress, :serial,:mac, :cpu, :access_time)";
                $stmt = $pdo->prepare($sql_insert);
                $stmt->execute([
                    ':ip_adress' => $ip_adress,
                    ':serial' => $serial,
                    ':mac' => $mac,
                    ':cpu' => $cpu,
                    ':access_time' => $access_time,
                ]);
                $processed++;
                $line_count++;
            }
        $_SESSION['logfile_position'] = ftell($handle); // aktuelle Position merken
        $_SESSION['logfile_line'] = $line_count;

        if (!feof($handle)) {
            echo "🔄 $line_count Zeilen verarbeitet. Nächster Block folgt...";
            echo "<meta http-equiv='refresh' content='1'>"; // in 1 Sekunde neu laden
            flush();
            usleep(100000);
        } else {
            echo "✅ Import abgeschlossen: $line_count Zeilen.";
            session_destroy();
        }
    } else {
        echo "<div> - Die Datei <strong>" . basename($filename) . "</strong> existiert nicht!</div>";
    }
}

// get 10 Lizenz-Seriennummern, die am häufigsten versuchen, auf den Server zuzugreifen
function get_frequent_license($pdo)
{
    $license = $pdo->query("
        SELECT serial, access_time, COUNT(*) AS access_count
        FROM log_entries
        WHERE serial IS NOT NUll AND access_time IS NOT NULL
        GROUP BY serial
        ORDER BY access_count DESC
        LIMIT 10
    ");

//    Tabelle mit Ergebnissen
    echo "<div class ='tables'><h3>Top 10 der meistgenutzten Lizenz-Seriennummern</h3>";
    echo '<table style="border: 1px solid #000000;">
        <tr>
            <th style="border: 1px solid #000000; padding: 5px 10px;">Platz</th>
            <th style="border: 1px solid #000000; padding: 5px 10px;">Lizens-Seriennummer</th>
            <th style="border: 1px solid #000000; padding: 5px 10px;">Anzhal des Zugriffs</th>
            <th style="border: 1px solid #000000; padding: 5px 10px;">Datum des Zugriffs</th>
        </tr>' . get_rows($license).'</table></div>';
}
function get_rows($license)
{
    $rows = '';
    $i = 0;
    foreach ($license as $row) {
        $i++;
        $datum = new DateTime($row['access_time']);
        $datum = $datum->format("Y-m-d");
        $rows .= '<tr>
                <td style="border-bottom: 1px solid #000000;  border-left: 1px solid #000000; border-right: 1px solid #000000; padding: 5px 10px;">' . $i . '</td>
                <td style="border-bottom: 1px solid #000000;  border-left: 1px solid #000000; border-right: 1px solid #000000; padding: 5px 10px;">' . $row['serial'] . '</td>
                <td style="border-bottom: 1px solid #000000;  border-right: 1px solid #000000; padding: 5px 10px; text-align: center;">' . $row['access_count'] . '</td>
                <td style="border-bottom: 1px solid #000000;border-right: 1px solid #000000; text-align: center;">' . $datum . '</td>
            </tr>';
    }
    return $rows;
}
//    Jedes Gerät hat eine unique MAC-Adresse => durch Erfassun und Zuordnung der
// MAC-Adresse bei jeder Lizenseabfrage kann ein Gerät eindeutig identifiziert werden
function get_count_of_license_on_same_device($pdo) {

    $license_repeat = $pdo->query("
        SELECT serial, mac, COUNT(mac) AS device_count
        FROM log_entries
        WHERE serial IS NOT NUll AND access_time IS NOT NULL AND mac IS NOT NULL
        GROUP BY serial
        ORDER BY device_count DESC
        LIMIT 10
    ");
    // Tabelle
    echo "<div class='tables'><h3>Verstöße gegen Ein-Gerät-Regel: Die 10 auffälligsten Lizenz-Seriennummern</h3>";
    echo '<table style="border: 1px solid #000000;">
        <tr>
            <th style="border: 1px solid #000000; padding: 5px 10px;">Platz</th>
            <th style="border: 1px solid #000000; padding: 5px 10px;">Lizens-Seriennummer</th>
             <th style="border: 1px solid #000000; padding: 5px 10px;">MAC-Adresse</th>
            <th style="border: 1px solid #000000; padding: 5px 10px;">Anzhal des Geräts</th>          
        </tr>' . get_rows_device($license_repeat)."</table></div>";
}
function get_rows_device($license_repeat) {
    $rows = '';
    $i = 0;
    foreach ($license_repeat as $row) {
        $i++;
        $rows .= '<tr>
                <td style="border-bottom: 1px solid #000000;  border-left: 1px solid #000000; border-right: 1px solid #000000; padding: 5px 10px;">' . $i . '</td>
                <td style="border-bottom: 1px solid #000000;  border-left: 1px solid #000000; border-right: 1px solid #000000; padding: 5px 10px;">' . $row['serial'] . '</td>
                <td style="border-bottom: 1px solid #000000;  border-left: 1px solid #000000; border-right: 1px solid #000000; padding: 5px 10px;">' . $row['mac'] . '</td>
                <td style="border-bottom: 1px solid #000000;  border-right: 1px solid #000000; padding: 5px 10px; text-align: center;">' . $row['device_count'] . '</td>
            </tr>';
    }
    return $rows;
}


?>
<h1>Analysiere die Logdatei</h1>
<div class="button-wrapper">
    <div class="import">
        <form method="get">
            <button class="buttons" type="submit" name="log_import">Daten importieren</button>
        </form>
    </div>
    <div class="tables">
        <form method="post">
            <button class="buttons" type="submit" name="evaluation">Auswerten</button>
        </form>
    </div>
</div>
<div class="status">
    <?php
    if (isset($_GET['log_import'])) {
        save_log_file($pdo, $filename,$lines_per_run);
    } ?>
</div>
<div class="results">
    <?php
    if (isset($_POST['evaluation'])) {
        echo "<div class='results_wraper'>";
        get_frequent_license($pdo);
        get_count_of_license_on_same_device($pdo);
        echo "</div>";
    }
    ?>
</div>
</body>
</html>