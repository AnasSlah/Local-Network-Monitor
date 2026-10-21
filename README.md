# 🛡️ Local Network IPS/IDS Monitor

A lightweight Intrusion Prevention and Detection System (IPS/IDS) designed to monitor local network traffic, detect unauthorized devices, and manage access control seamlessly.

## 🚀 Features
* **Real-Time Device Discovery:** Utilizes aggressive Python ARP scanning to detect connected devices instantly.
* **Smart Dashboard:** A responsive PHP/MySQL web interface to manage network devices.
* **Access Control:** 
  * ✅ Trust known devices.
  * ⏳ Schedule internet access (e.g., allow from 08:00 AM to 10:00 PM).
  * 🚫 Permanently ban unknown/suspicious MAC addresses.
* **Automated Threat Response:** Unknown devices are automatically flagged as suspicious and can be dropped from the network.

## 🛠️ Tech Stack
* **Backend:** Python (Multithreading, Subprocess) for network scanning.
* **Frontend & Dashboard:** PHP, HTML, CSS, JavaScript (AJAX for live updates).
* **Database:** MySQL.

## ⚙️ How It Works
1. `scanner.py` runs in the background, continuously pinging the subnet and reading the ARP table to find active MAC addresses.
2. It updates the MySQL database with device statuses (Trusted, Suspicious, Banned).
3. `index.php` serves as the admin dashboard to review devices and assign actions (Trust, Scheduled Ban, Perm-Ban, Delete) without needing page reloads.

## 📸 Screenshots
*(Add a screenshot of your dashboard here)*
