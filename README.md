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
   - `dotenv`
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
   pip install requests python-dotenv
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

1. **Create a `.env` File**:
   In the directory where your script is located, create a `.env` file and add the following configurations:
   ```bash
   TELEGRAM_TOKEN=your_telegram_token_here
   CHAT_ID=your_chat_id_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   LOG_FILE=/var/log/auth.log
   FAILED_ATTEMPTS_FILE=failed_attempts.json
   MAX_FAILED_ATTEMPTS=3
   IPSET_NAME=ssh_block_list
   BLOCK_TIMEOUT=2147483
   MAX_REPORTS_PER_MINUTE=10
   ```

2. **Hostname Mapping**:
   You can customize the hostnames by modifying the `HOSTNAME_MAP` dictionary directly in the script:
   ```python
   HOSTNAME_MAP = {
       'hostname': "custom hostname",
       'addmore': "custom hostnames",
   }
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
