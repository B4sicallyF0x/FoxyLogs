# FoxyLogs

A simple Python script that monitors SSH login attempts. After detecting 3 invalid attempts from the same IP address, the script reports the IP to AbuseIPDB, blocks it using ipset, and sends a notification via a Telegram Bot.

## Features

- Monitors SSH login attempts from the auth.log file.
- Detects multiple failed login attempts from the same IP address.
- Blocks IPs using `ipset` and `iptables`.
- Reports the IP to AbuseIPDB.
- Sends notifications via a Telegram Bot.

## Prerequisites

1. **Python 3.x**
2. **Dependencies**:
   - `requests`
   - `json`
   - `re`
   - `subprocess`
   - `time`
3. **System Tools**:
   - `ipset`
   - `iptables`

## Installation

1. **Install Python**:
   Ensure you have Python 3.x installed. You can check your Python version using:
   ```bash
   python3 --version
   ```

2. **Install Dependencies**:
   Install the required Python packages using pip:
   ```bash
   pip install requests
   ```

3. **Install System Tools**:
   Ensure `ipset` and `iptables` are installed on your system. You can install them using:
   ```bash
   sudo apt update
   sudo apt install ipset iptables
   ```

4. **Set Up Telegram Bot**:
   - Create a Telegram Bot using BotFather and obtain the API token.
   - Obtain your [chat ID](https://gist.github.com/nafiesl/4ad622f344cd1dc3bb1ecbe468ff9f8a).

5. **Set Up AbuseIPDB**:
   - Sign up at [AbuseIPDB](https://www.abuseipdb.com/) and obtain your API key.

## Configuration

1. **Telegram Bot Configuration**:
   Replace the `TELEGRAM_TOKEN` and `CHAT_ID` in the script with your actual token and chat ID.
   ```python
   TELEGRAM_TOKEN = 'YOUR_TELEGRAM_TOKEN'
   CHAT_ID = 'YOUR_CHAT_ID'
   ```

2. **AbuseIPDB Configuration**:
   Replace the `ABUSEIPDB_API_KEY` with your actual API key.
   ```python
   ABUSEIPDB_API_KEY = 'YOUR_ABUSEIPDB_API_KEY'
   ```

3. **Hostname Mapping**:
   You can customize the hostnames by modifying the `HOSTNAME_MAP` dictionary.
   ```python
   HOSTNAME_MAP = {
       'hostname': "custom hostname",
       'addmore': "custom hostnames",
   }
   ```

4. **Log File Location**:
   By default, the script monitors `/var/log/auth.log`. If your SSH log file is in a different location, update the `LOG_FILE` variable.
   ```python
   LOG_FILE = '/path/to/your/auth.log'
   ```

5. **Max Failed Attempts**:
   The default maximum failed attempts before banning an IP is set to 3. You can change this by modifying the `MAX_FAILED_ATTEMPTS` variable.
   ```python
   MAX_FAILED_ATTEMPTS = 3
   ```

6. **Block Timeout**:
   The default block timeout is set to 24 days. You can change this by modifying the `BLOCK_TIMEOUT` variable.
   ```python
   BLOCK_TIMEOUT = 2147483
   ```

## Running the Script

1. Ensure the script has execute permissions:
   ```bash
   chmod +x FoxyLogs.py
   ```

2. Run the script:
   ```bash
   sudo python3 FoxyLogs.py
   ```
