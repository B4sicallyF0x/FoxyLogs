import re
import time
import subprocess
import requests
import json
from collections import deque
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

# Load .env
load_dotenv()

# Load .env
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
CHAT_ID = os.getenv('CHAT_ID')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
LOG_FILE = os.getenv('LOG_FILE', '/var/log/auth.log')
FAILED_ATTEMPTS_FILE = os.getenv('FAILED_ATTEMPTS_FILE', 'failed_attempts.json')
MAX_FAILED_ATTEMPTS = int(os.getenv('MAX_FAILED_ATTEMPTS', 3))
IPSET_NAME = os.getenv('IPSET_NAME', 'ssh_block_list')
BLOCK_TIMEOUT = int(os.getenv('BLOCK_TIMEOUT', 2147483))
MAX_REPORTS_PER_MINUTE = int(os.getenv('MAX_REPORTS_PER_MINUTE', 10))

# Custom Hostname Map (for the Telegram notification)
HOSTNAME_MAP = {
    'hostname': "custom hostname",
    'addmore': "custom hostnames",
}

report_times = deque(maxlen=MAX_REPORTS_PER_MINUTE)

def get_custom_hostname():
    """Gets the hostname and maps it to the custom name if needed."""
    hostname = subprocess.check_output('hostname', shell=True).strip().decode()
    return HOSTNAME_MAP.get(hostname, hostname)

def send_telegram_message(message):
    """Sends the message to the Telegram Bot."""
    API_URL = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    payload = {
        'chat_id': CHAT_ID,
        'text': message
    }
    requests.post(API_URL, data=payload)

def can_report_ip():
    """Checks if the script can report another IP based on the time limit."""
    current_time = datetime.now()

    # Clear any reports older than a minute
    while report_times and (current_time - report_times[0] > timedelta(minutes=1)):
        report_times.popleft()

    if len(report_times) < MAX_REPORTS_PER_MINUTE:
        report_times.append(current_time)
        return True
    else:
        return False

def report_to_abuseipdb(ip):
    """Reports IP to AbuseIPDB."""
    if not can_report_ip():
        print(f'Rate limit reached. Cannot report IP {ip} at this time.')
        return

    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Content-Type': 'application/json'
    }
    data = {
        'ip': ip,
        'categories': '18',  # Brute-Force
        'comment': 'Detected multiple failed SSH login attempts'
    }
    response = requests.post('https://api.abuseipdb.com/api/v2/report', headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print(f'IP {ip} reported to AbuseIPDB')
    else:
        print(f'Failed to report IP {ip} to AbuseIPDB: {response.status_code}')

def block_ip(ip):
    """Blocks IP using ipset and iptables."""
    subprocess.run(['ipset', 'add', IPSET_NAME, ip, 'timeout', str(BLOCK_TIMEOUT)], check=True)
    subprocess.run(['iptables', '-I', 'INPUT', '-m', 'set', '--match-set', IPSET_NAME, 'src', '-j', 'DROP'], check=True)
    print(f'IP {ip} blocked with ipset and iptables')

def load_failed_attempts():
    """Loads failed attempts from file."""
    try:
        with open(FAILED_ATTEMPTS_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

def save_failed_attempts(failed_attempts):
    """Saves attempt log on file."""
    with open(FAILED_ATTEMPTS_FILE, 'w') as file:
        json.dump(failed_attempts, file)

def ensure_ipset_exists():
    """Ensures that ipset exists."""
    try:
        subprocess.run(['ipset', 'list', IPSET_NAME], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        subprocess.run(['ipset', 'create', IPSET_NAME, 'hash:ip', 'timeout', str(BLOCK_TIMEOUT)], check=True)

def monitor_ssh_log():
    """Monitors log file."""
    failed_attempts = load_failed_attempts()
    ensure_ipset_exists()

    try:
        with open(LOG_FILE, 'r') as file:
            file.seek(0, 2)

            while True:
                line = file.readline()
                if not line:
                    time.sleep(1)
                    continue
                
                # Searches for SSH attempts
                if 'Failed password' in line:
                    # Gets IP and username
                    ip_match = re.search(r'from (\S+)', line)
                    user_match = re.search(r'for (invalid user \S+|user \S+)', line)
                    
                    if ip_match and user_match:
                        ip = ip_match.group(1)
                        user = user_match.group(1).replace('invalid user ', '').replace('user ', '')
                        hostname = get_custom_hostname()

                        # Adds +1 to attempts
                        if ip not in failed_attempts:
                            failed_attempts[ip] = 0
                        failed_attempts[ip] += 1
                        save_failed_attempts(failed_attempts)

                        # Verifies if ban is needed
                        if failed_attempts[ip] >= MAX_FAILED_ATTEMPTS:
                            block_ip(ip)
                            report_to_abuseipdb(ip)
                            message = (f'Failed SSH Login Attempt Blocked and Reported!\n'
                                       f'With the IP: {ip}\n'
                                       f'Using the username: {user}\n'
                                       f'On your {hostname}')
                            send_telegram_message(message)
                            # Resets failed attempts
                            failed_attempts[ip] = 0
                            save_failed_attempts(failed_attempts)

    except FileNotFoundError:
        print(f'Error: Log file {LOG_FILE} not found')
    except Exception as e:
        print(f'Error: {e}')

if __name__ == '__main__':
    monitor_ssh_log()
