import subprocess
import concurrent.futures
import mysql.connector
import time
import winsound

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'network_monitor'
}

def ping_device(ip):
    subprocess.call(['ping', '-n', '1', '-w', '100', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def aggressive_sweep(subnet="192.168.1."):
    ips = [f"{subnet}{i}" for i in range(1, 255)]
    
    # ⚡ الوزنية المثالية: 100 مسار تمنع اختناق المعالج وتسرع الحذف
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(ping_device, ips)

    devices = []
    try:
        arp_output = subprocess.check_output("arp -a", shell=True, text=True)
        for line in arp_output.splitlines():
            if "dynamic" in line.lower() or "ديناميكي" in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1].lower().replace('-', ':')
                    if not ip.startswith("224.") and not ip.startswith("239.") and not ip.startswith("255."):
                        devices.append({'ip': ip, 'mac': mac})
    except Exception:
        pass
    return devices

def check_and_alert(devices):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        print(f"[+] Lightning Sweep: Found {len(devices)} active devices.")

        live_macs = []
        for device in devices:
            mac = device['mac']
            ip = device['ip']
            live_macs.append(mac)
            
            cursor.execute("SELECT * FROM devices WHERE mac_address = %s", (mac,))
            result = cursor.fetchone()

            if result:
                cursor.execute("UPDATE devices SET last_seen = CURRENT_TIMESTAMP, ip_address = %s WHERE mac_address = %s", (ip, mac))
            else:
                print(f"[!] ALARM: Target Locked! IP: {ip} | MAC: {mac}")
                winsound.Beep(2000, 300) 
                cursor.execute("INSERT INTO devices (ip_address, mac_address, device_name, status) VALUES (%s, %s, '📱 جهاز ذكي', 'suspicious')", (ip, mac))

        # ⚡ سرعة الاستجابة: تم تقليل المهلة إلى 10 ثواني للحذف اللحظي
        if live_macs:
            format_strings = ','.join(['%s'] * len(live_macs))
            delete_query = f"DELETE FROM devices WHERE status = 'suspicious' AND last_seen < NOW() - INTERVAL 10 SECOND AND mac_address NOT IN ({format_strings})"
            cursor.execute(delete_query, tuple(live_macs))
        else:
            cursor.execute("DELETE FROM devices WHERE status = 'suspicious' AND last_seen < NOW() - INTERVAL 10 SECOND")

        conn.commit()
    except Exception as e:
        pass
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

print(">>> IDS Ultra-Fast Radar Active... (Press Ctrl+C to stop)")
while True:
    try:
        discovered_devices = aggressive_sweep("192.168.1.")
        if discovered_devices:
            check_and_alert(discovered_devices)
        time.sleep(0.5)
    except KeyboardInterrupt:
        break