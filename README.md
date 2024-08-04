# FoxyLogs
A simple Python script that monitors SSH login attempts. After detecting 3 invalid attempts from the same IP address, the script reports the IP to AbuseIPDB, blocks it using ipset, and sends a notification via a Telegram Bot
