<?php
$host = 'localhost';
$db   = 'network_monitor';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$pdo = new PDO($dsn, $user, $pass);

// معالجة أوامر الأزرار
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['mac']) && isset($_POST['action'])) {
    $mac = $_POST['mac'];
    $action = $_POST['action'];
    
    if ($action === 'trust') {
        $sql = "UPDATE devices SET status = 'trusted', ban_until = NULL, ban_start_time = NULL, ban_end_time = NULL WHERE mac_address = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$mac]);
    } elseif ($action === 'untrust') {
        $sql = "UPDATE devices SET status = 'suspicious', ban_until = NULL, ban_start_time = NULL, ban_end_time = NULL WHERE mac_address = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$mac]);
    } elseif ($action === 'scheduled_ban') {
        $start = !empty($_POST['ban_start']) ? $_POST['ban_start'] : null;
        $end = !empty($_POST['ban_end']) ? $_POST['ban_end'] : null;
        if ($start && $end) {
            $sql = "UPDATE devices SET status = 'scheduled_ban', ban_start_time = ?, ban_end_time = ? WHERE mac_address = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$start, $end, $mac]);
        }
    } elseif ($action === 'perm_ban') {
        $sql = "UPDATE devices SET status = 'perm_ban', ban_until = NULL, ban_start_time = NULL, ban_end_time = NULL WHERE mac_address = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$mac]);
    } elseif ($action === 'delete') {
        $sql = "DELETE FROM devices WHERE mac_address = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$mac]);
    }
    
    header("Location: index.php");
    exit();
}

$stmt = $pdo->query("SELECT * FROM devices ORDER BY CASE WHEN id IN (1, 2) THEN 1 ELSE 2 END, last_seen DESC");
$devices = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نظام منع الاختراق (IPS/IDS)</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f1f5f9; margin: 0; padding: 15px; }
        .container { max-width: 1050px; margin: 0 auto; background: white; border-radius: 12px; padding: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); border-top: 5px solid #0f172a; }
        h1 { text-align: center; color: #0f172a; font-size: 24px; margin-bottom: 25px; }
        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 850px; text-align: right; }
        th { background-color: #0f172a; color: white; padding: 12px 15px; font-size: 14px; }
        td { padding: 12px 15px; border-bottom: 1px solid #e2e8f0; font-size: 14px; color: #334155; vertical-align: middle; }
        tr:hover { background-color: #f8fafc; }
        
        .badge { padding: 5px 10px; border-radius: 20px; font-weight: bold; font-size: 12px; display: inline-block; }
        .badge-green { background-color: #dcfce3; color: #15803d; }
        .badge-yellow { background-color: #fef08a; color: #854d0e; }
        .badge-orange { background-color: #fed7aa; color: #c2410c; }
        .badge-red { background-color: #fee2e2; color: #b91c1c; }
        
        .btn { padding: 6px 12px; border: none; border-radius: 6px; color: white; cursor: pointer; font-size: 12px; font-weight: bold; transition: 0.2s; }
        .btn-blue { background-color: #3b82f6; } .btn-blue:hover { background-color: #2563eb; }
        .btn-gray { background-color: #64748b; } .btn-gray:hover { background-color: #475569; }
        .btn-orange { background-color: #f59e0b; } .btn-orange:hover { background-color: #d97706; }
        .btn-red { background-color: #ef4444; } .btn-red:hover { background-color: #dc2626; }
        .btn-dark { background-color: #1e293b; } .btn-dark:hover { background-color: #0f172a; }
        
        .font-mono { font-family: monospace; direction: ltr; display: inline-block; font-size: 13px; }
        .core-device { color: #64748b; font-size: 12px; font-weight: bold; background: #f1f5f9; padding: 5px 10px; border-radius: 5px;}
        
        .actions-container { display: flex; flex-direction: column; gap: 10px; align-items: center; margin: 0; }
        .main-btn-group { display: flex; gap: 6px; justify-content: center; flex-wrap: wrap; }
        .time-group { display: flex; gap: 6px; align-items: center; background: #f8fafc; padding: 6px 12px; border-radius: 8px; border: 1px dashed #cbd5e1; }
        .time-input { padding: 4px; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 12px; outline: none; background: white; text-align: center; }
        .time-label { font-size: 12px; color: #475569; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>لوحة التحكم ومنع الاختراقات (IPS/IDS)</h1>
        
        <div id="refresh-container">
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>اسم الجهاز</th>
                            <th>عنوان IP</th>
                            <th>عنوان MAC</th>
                            <th style="text-align: center;">الحالة الأمنية</th>
                            <th style="text-align: center;">الإجراءات</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($devices as $device): ?>
                        <tr>
                            <td style="font-weight: bold; color: #1e293b;">
                                <?= htmlspecialchars($device['device_name'] ? $device['device_name'] : 'جهاز غير معروف') ?>
                            </td>
                            <td><span class="font-mono" style="color: #2563eb;"><?= htmlspecialchars($device['ip_address']) ?></span></td>
                            <td><span class="font-mono"><?= htmlspecialchars($device['mac_address']) ?></span></td>
                            <td style="text-align: center;">
                                <?php if ($device['status'] === 'trusted'): ?>
                                    <span class="badge badge-green">موثوق</span>
                                <?php elseif ($device['status'] === 'scheduled_ban'): ?>
                                    <span class="badge badge-orange">محظور (<?= substr($device['ban_start_time'], 0, 5) ?> - <?= substr($device['ban_end_time'], 0, 5) ?>)</span>
                                <?php elseif ($device['status'] === 'perm_ban'): ?>
                                    <span class="badge badge-red">محظور نهائياً</span>
                                <?php else: ?>
                                    <span class="badge badge-yellow">مشبوه (ينتظر)</span>
                                <?php endif; ?>
                            </td>
                            <td style="text-align: center;">
                                <?php if ($device['id'] == 1 || $device['id'] == 2): ?>
                                    <span class="core-device">جهاز أساسي</span>
                                <?php else: ?>
                                    <form method="POST" class="actions-container">
                                        <input type="hidden" name="mac" value="<?= htmlspecialchars($device['mac_address']) ?>">
                                        
                                        <div class="main-btn-group">
                                            <!-- زر التوثيق / إلغاء التوثيق -->
                                            <?php if ($device['status'] === 'trusted'): ?>
                                                <button type="submit" name="action" value="untrust" class="btn btn-gray" formnovalidate>إلغاء التوثيق</button>
                                            <?php else: ?>
                                                <button type="submit" name="action" value="trust" class="btn btn-blue" formnovalidate>توثيق</button>
                                            <?php endif; ?>
                                            
                                            <!-- زر الحظر النهائي / فك الحظر -->
                                            <?php if ($device['status'] === 'scheduled_ban' || $device['status'] === 'perm_ban'): ?>
                                                <button type="submit" name="action" value="untrust" class="btn btn-gray" formnovalidate>فك الحظر</button>
                                            <?php else: ?>
                                                <button type="submit" name="action" value="perm_ban" class="btn btn-red" formnovalidate>حظر نهائي</button>
                                            <?php endif; ?>
                                            
                                            <button type="submit" name="action" value="delete" class="btn btn-dark" formnovalidate onclick="return confirm('هل أنت متأكد من حذف هذا الجهاز نهائياً؟');">حذف</button>
                                        </div>

                                        <!-- الحظر المجدول يظهر دائماً ما لم يكن الجهاز محظوراً بالفعل -->
                                        <?php if ($device['status'] !== 'scheduled_ban' && $device['status'] !== 'perm_ban'): ?>
                                            <div class="time-group">
                                                <span class="time-label">من:</span>
                                                <input type="time" name="ban_start" class="time-input" required>
                                                <span class="time-label">إلى:</span>
                                                <input type="time" name="ban_end" class="time-input" required>
                                                <button type="submit" name="action" value="scheduled_ban" class="btn btn-orange">حظر مجدول</button>
                                            </div>
                                        <?php endif; ?>
                                        
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        let isInputFocused = false;
        document.addEventListener('focusin', function(e) {
            if (e.target && e.target.classList.contains('time-input')) {
                isInputFocused = true;
            }
        });
        document.addEventListener('focusout', function(e) {
            if (e.target && e.target.classList.contains('time-input')) {
                isInputFocused = false;
            }
        });

        setInterval(function() {
            if (!isInputFocused) {
                fetch(window.location.href)
                    .then(response => response.text())
                    .then(html => {
                        let parser = new DOMParser();
                        let doc = parser.parseFromString(html, 'text/html');
                        let newContent = doc.querySelector('#refresh-container').innerHTML;
                        document.querySelector('#refresh-container').innerHTML = newContent;
                    })
                    .catch(error => console.log('Error fetching data:', error));
            }
        }, 1000);
    </script>
</body>
</html>