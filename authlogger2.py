import argparse
import configparser
import datetime
import errno
import os
import pickle
import signal
import subprocess
import sys
import time
from typing import Optional


debugmode = False
version = "v2.0-2026/02/27r0"


class cBlock:
    def __init__(self, vDT=None, ip=None, vReason=None, vUsername=None):
        self.aDateTime = []
        self.ip = ip
        self.aReason = []
        self.aUsername = []

    def add_datetime(self, vDT):
        self.aDateTime.append(vDT)

    def add_reason(self, vReason):
        self.aReason.append(vReason)

    def add_username(self, vUsername):
        self.aUsername.append(vUsername)


class AuthLogger2:
    def __init__(self):
        self.debugmode = False
        self.slash = '/'
        self.start_dir = os.getcwd().removesuffix(self.slash)

        self.logging_enabled = True
        self.log_file_name = ''
        self.log_file_handle = None
        self.new_log_data = False

        self.ini_file_name = ''
        self.block_file_name = ''
        self.auth_file_name = ''
        self.vnc_file_name = ''
        self.kern_file_name = ''

        self.auth_exists = False
        self.vnc_exists = False
        self.kern_exists = False

        self.auth_file_handle = None
        self.vnc_file_handle = None
        self.kern_file_handle = None

        self.auth_pos = 0
        self.vnc_pos = 0
        self.kern_pos = 0

        self.auth_inode = None
        self.vnc_inode = None
        self.kern_inode = None

        self.failcount = 2
        self.restart_time = 'None'
        self.local_ip = '192.168.'
        self.aIgnoreIPs = []
        self.sAutoBlockUsers = ''
        self.aAutoBlockUsers = []

        self.aBlocklist = []
        self.aActiveBlocklist = []

        self.iptables_available = False
        self.last_checkin_hour = ''

        self.flush_count = 80
        self.flush_tick = 0
        self.run_tick = 0
        self.run_every = 4

        self.auth_blocks = False
        self.vnc_blocks = False
        self.kern_blocks = False
        self.block_status = False

    def clear_screen(self):
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')

    def help(self):
        print("**something went wrong. I don't know what, it probably means a file didn't exist or you ran as a normie rather than root\n")
        print("Remember: must run as sudo/root or it cannot block IPs\n")

    def error_arg(self, err: int):
        match err:
            case 0:
                print("bye!")
            case 1:
                print("no worries, bye!")
            case 2:
                self.help()
            case 3:
                print("**NEEDS TO RUN AS (SUDO) ROOT, or it cannot access auth.log and set iptables rules")
                self.help()
            case 4:
                print("got stuck in a loop")
            case 5:
                print("unable to create or write to logfile")
            case 6:
                print("settings.ini file not found.")
            case 7:
                print("auth.log file not found.")
            case 8:
                print("settings.ini failed to load correctly.")
            case 9:
                print("vnc log file not found.")
            case 10:
                print("neither auth.log nor vnc log file found/loaded.")
            case 11:
                print("for some reason, end of main() was reached. This should not have happened :(")
            case 12:
                print("Exiting because restart time is met.")
            case 13:
                print("Ctrl-C detected, exiting gracefully.")
            case 14:
                print("Shutdown demanded")
            case 15:
                print("Error creating logfile directory.")
            case 16:
                print("iptables not found or not installed. Cannot block IPs without iptables.")
            case 17:
                print("Error writing to blocklist file. Check permissions.")
            case _:
                print("dunno, but bye!")
        sys.exit(err)

    def check_is_linux(self):
        if not sys.platform.startswith('linux'):
            self.slash = '\\'
            self.debugmode = True
            print("not running on linux, debug mode enabled")

    def welcome(self):
        print('\n[==-- Wheel reinvention society presents: authlogger2! --==]\n')
        print('Does what authlogger does, but cleaner.\n')
        print("To EXIT use CTRL-C.")
        print('version: ' + version)

    def timestamp(self) -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    def log_data(self, message: str):
        print(f"[{self.timestamp()}]:{message}")
        if self.logging_enabled and self.log_file_handle is not None:
            self.check_log_size()
            self.log_file_handle.write(f"[{self.timestamp()}]:{message}\n")
            self.new_log_data = True

    def flush_log_file(self):
        if not self.logging_enabled:
            return
        if self.log_file_handle is not None:
            self.log_file_handle.flush()
            self.new_log_data = False

    def close_log_file(self):
        if not self.logging_enabled:
            return
        if self.log_file_handle is None:
            return
        self.log_data('authlogger stopped.\n')
        self.flush_log_file()
        self.log_file_handle.close()
        self.log_file_handle = None

    def open_log_file(self):
        if not self.logging_enabled:
            print('-- logging to file is off --')
            return

        log_dir = self.start_dir + self.slash + 'logs'
        if not os.path.isdir(log_dir):
            try:
                os.mkdir(log_dir)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    self.logging_enabled = False
                    self.close_gracefully(exitcode=15)
                else:
                    print("log directory already exists, but should not be here as OS said it wasn't here")

        self.log_file_name = log_dir + self.slash + 'authlogger.log'
        try:
            self.log_file_handle = open(self.log_file_name, 'a')
        except Exception:
            print('error opening logfile')
            self.error_arg(5)
        self.log_data('authlogger2 started. Version: ' + version)

    def check_log_size(self):
        if not self.logging_enabled:
            return
        if not self.log_file_name:
            return
        if os.path.isfile(self.log_file_name):
            if os.stat(self.log_file_name).st_size > (1024 * 1024 * 10):
                print('Cycling logfile')
                self.flush_log_file()
                if self.log_file_handle is not None:
                    self.log_file_handle.close()
                try:
                    if os.path.isfile(self.log_file_name + '.old'):
                        if os.path.isfile(self.log_file_name + '.old.1'):
                            os.remove(self.log_file_name + '.old.1')
                        os.rename(self.log_file_name + '.old', self.log_file_name + '.old.1')
                    os.rename(self.log_file_name, self.log_file_name + '.old')
                except OSError:
                    print('error renaming logfile')
                    self.error_arg(6)
                self.open_log_file()

    def get_args(self):
        self.log_data('getting args')
        parser = argparse.ArgumentParser()
        parser.add_argument('-n', '--nolog', action='store_false', help='turn off logging to disk')
        args = parser.parse_args()
        self.logging_enabled = args.nolog

        self.ini_file_name = self.start_dir + self.slash + 'settings.ini'
        if not self.load_settings():
            self.error_arg(8)

    def split_local_ip(self, ip_list: str):
        self.aIgnoreIPs = [x.strip() for x in ip_list.split(',') if x.strip()]
        self.log_data('local IP list: ' + str(self.aIgnoreIPs))

    def split_auto_block_users(self, user_list: str):
        user_list = user_list.upper()
        self.log_data('autoblock users: ' + str(user_list))
        self.aAutoBlockUsers = [x.strip() for x in user_list.split(',') if x.strip()]

    def check_local_ip(self, check_string: str) -> bool:
        for item in self.aIgnoreIPs:
            if item in check_string:
                return True
        return False

    def check_auto_block_users(self, username: str) -> bool:
        username = (username or '').strip().upper()
        if username == '':
            return False
        if self.debugmode:
            print('checking user: ' + username)
        for item in self.aAutoBlockUsers:
            if item == username:
                if self.debugmode:
                    print('bad user: ' + username)
                return True
        return False

    def load_settings(self) -> bool:
        self.log_data('loading settings')

        self.local_ip = '192.168.'
        self.failcount = 2
        self.restart_time = 'None'

        self.block_file_name = self.start_dir + self.slash + 'blocklist.dat'
        if not self.debugmode:
            self.auth_file_name = '/var/log/auth.log'
            self.vnc_file_name = '/var/log/vncserver-x11.log'
            self.kern_file_name = '/var/log/kern.log'
        else:
            self.auth_file_name = self.start_dir + self.slash + 'auth.log'
            self.vnc_file_name = self.start_dir + self.slash + 'vncserver-x11.log'
            self.kern_file_name = self.start_dir + self.slash + 'kern.log'

        loaded_ok = True
        if os.path.isfile(self.ini_file_name):
            self.log_data('reading settings.ini')
            config = configparser.ConfigParser()
            try:
                config.read(self.ini_file_name)
                self.local_ip = config.get('Settings', 'LocalIP', fallback='192.168.')
                if not self.debugmode:
                    self.block_file_name = config.get('Settings', 'blockfile', fallback=self.block_file_name)
                    self.auth_file_name = config.get('Settings', 'authfile', fallback=self.auth_file_name)
                    self.kern_file_name = config.get('Settings', 'kernfile', fallback=self.kern_file_name)
                    self.vnc_file_name = config.get('Settings', 'vncfile', fallback=self.vnc_file_name)

                fc = config.get('Settings', 'failcount', fallback='2')
                self.restart_time = config.get('Settings', 'restart_time', fallback='None')
                self.sAutoBlockUsers = config.get('Settings', 'autoblockusers', fallback='')
                try:
                    self.failcount = int(fc)
                except ValueError:
                    self.log_data('error: failcount is not an integer, using default of 2: received-->' + fc)
                    self.failcount = 2
                self.log_data('loaded settings.ini:')
            except Exception:
                self.log_data('error loading settings.ini')
                loaded_ok = False

        self.split_auto_block_users(self.sAutoBlockUsers)

        self.auth_exists = os.path.isfile(self.auth_file_name)
        self.vnc_exists = os.path.isfile(self.vnc_file_name)
        self.kern_exists = os.path.isfile(self.kern_file_name)

        self.log_data(f"LocalIP(ini): {self.local_ip}")
        self.split_local_ip(self.local_ip)
        self.log_data(f"blockfile: {self.block_file_name}")
        if self.auth_exists:
            self.log_data(f"authfile: {self.auth_file_name}")
        if self.vnc_exists:
            self.log_data(f"vncfile: {self.vnc_file_name}")
        if self.kern_exists:
            self.log_data(f"kernfile: {self.kern_file_name}")
        self.log_data(f"failcount: {self.failcount}")
        self.log_data(f"restart_time: {self.restart_time}")

        return loaded_ok

    def save_settings(self):
        if os.path.isfile(self.ini_file_name):
            return

        self.log_data('saving settings')
        config = configparser.ConfigParser()
        config['Settings'] = {
            'LocalIP': self.local_ip,
            'blockfile': self.block_file_name,
            'authfile': self.auth_file_name,
            'kernfile': self.kern_file_name,
            'failcount': str(self.failcount),
            'vncfile': self.vnc_file_name,
            'restart_time': self.restart_time,
            'autoblockusers': self.sAutoBlockUsers,
        }
        try:
            with open(self.ini_file_name, 'w') as configfile:
                config.write(configfile)
        except Exception as e:
            print('Exception: ', e)
            self.log_data('error saving settings.ini')

    def check_iptables_installed(self) -> bool:
        try:
            result = subprocess.run(['/sbin/iptables', '--version'], capture_output=True, timeout=1)
            if result.returncode == 0:
                self.iptables_available = True
                self.log_data('iptables found: ' + result.stdout.decode().strip())
                return True
            self.iptables_available = False
            self.log_data('iptables found but returned error code: ' + str(result.returncode))
            return False
        except FileNotFoundError:
            self.iptables_available = False
            self.log_data('iptables not found at /sbin/iptables')
            return False
        except subprocess.TimeoutExpired:
            self.iptables_available = False
            self.log_data('iptables check timed out')
            return False
        except Exception as e:
            self.iptables_available = False
            self.log_data('Error checking iptables: ' + str(e))
            return False

    def save_iptables(self):
        if not self.iptables_available:
            self.log_data('SaveIPTables skipped: iptables not available')
            return
        try:
            subprocess.call(['/sbin/iptables-save'])
        except Exception as e:
            self.log_data('Error saving iptables: ' + str(e))

    def clear_iptables(self):
        if self.debugmode:
            self.log_data('CLEAR/debug mode: iptables -F')
            return

        if not self.iptables_available:
            self.log_data('Skipping iptables clear - iptables not available')
            return

        self.log_data('clearing iptables and setting up port scan detection rules')
        try:
            subprocess.call(['/sbin/iptables', '-F'])
            subprocess.call(['/sbin/iptables', '-A', 'INPUT', '-p', 'tcp', '--syn', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set'])
            subprocess.call(['/sbin/iptables', '-A', 'INPUT', '-p', 'tcp', '--syn', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--update', '--seconds', '60', '--hitcount', '10', '-j', 'LOG', '--log-prefix', 'PORT_SCAN_DETECTED: '])
            subprocess.call(['/sbin/iptables-save'])
            self.log_data('done')
        except Exception as e:
            self.log_data('Error clearing iptables: ' + str(e))

    def is_valid_ip(self, ip: str) -> bool:
        if ip.count('.') != 3:
            return False
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isnumeric():
                return False
        return True

    def reverse_datetime(self, dt_string: str) -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.strptime(dt_string, '%Y%m%d%H%M%S'))

    def print_blocklist(self):
        self.log_data('printing blocklist')
        for idx, row in enumerate(self.aBlocklist):
            self.log_data(f"[{idx}] {row.ip}:")
            for i, dt in enumerate(row.aDateTime):
                username = row.aUsername[i] if i < len(row.aUsername) else ''
                reason = row.aReason[i] if i < len(row.aReason) else ''
                self.log_data('-->' + self.reverse_datetime(dt) + f" - u=[{username}] reason: {reason}")

    def block_ip(self, ip: str, reason: str = ''):
        if ip in self.aActiveBlocklist:
            self.log_data('already blocked: ' + ip)
            return

        self.aActiveBlocklist.append(ip)
        if self.debugmode:
            self.log_data('ADD/debug mode: iptables -I INPUT -s ' + ip + ' -j DROP')
            return

        if not self.iptables_available:
            self.log_data('NOT blocking IP ' + ip + ' - iptables not available: ' + reason)
            return

        self.log_data('Passing to IPTables ->' + ip + ' reason: ' + reason)
        try:
            subprocess.call(['/sbin/iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
        except Exception as e:
            self.log_data('Error blocking IP ' + ip + ': ' + str(e))
            if ip in self.aActiveBlocklist:
                self.aActiveBlocklist.remove(ip)

    def check_blocklist(self, ip: str, timeblocked: str, reason: str, user: str = '') -> bool:
        if not self.is_valid_ip(ip):
            return False

        found_it = False
        dtfound = -1
        for i, row in enumerate(self.aBlocklist):
            if row.ip == ip:
                dtfound = i
                for existing_dt in row.aDateTime:
                    if existing_dt == timeblocked:
                        found_it = True
                        break

        if not found_it:
            if dtfound >= 0:
                self.log_data(f"adding datetime: [{dtfound}] {ip} u=[{user}] r=[{reason}]")
                row = self.aBlocklist[dtfound]
                row.add_datetime(timeblocked)
                row.add_reason(reason)
                row.add_username(user)
                if self.check_auto_block_users(user):
                    self.block_ip(ip, 'bad user: ' + user)
                elif len(row.aDateTime) >= self.failcount:
                    self.block_ip(ip, 'failcount: ' + str(len(row.aDateTime)) + ' login failures from this IP')
            else:
                self.log_data(f"[{len(self.aBlocklist)}] adding: {ip} u=[{user}] r=[{reason}]")
                new_row = cBlock(ip=ip)
                new_row.add_datetime(timeblocked)
                new_row.add_reason(reason)
                new_row.add_username(user)
                self.aBlocklist.append(new_row)
                if self.check_auto_block_users(user):
                    self.block_ip(ip, 'bad user: ' + user)
                elif self.failcount == 1:
                    self.block_ip(ip, 'failcount: login failures set to 1')

        was_new = not found_it
        if self.debugmode and was_new:
            print('CBL-foundit')
        return was_new

    def get_datetime(self, line: str, source: str) -> str:
        try:
            if source in ('auth.log', 'kern.log'):
                first = line.split()[0]
                dt_obj = datetime.datetime.fromisoformat(first.split('+')[0])
                return dt_obj.strftime('%Y%m%d%H%M%S')

            if source == 'vncserver-x11.log':
                dt = line.split()[1]
                dt = dt[:10] + ' ' + dt[11:19]
                return time.strftime('%Y%m%d%H%M%S', time.strptime(dt, '%Y-%m-%d %H:%M:%S'))
        except Exception:
            pass

        try:
            now_year = time.strftime('%Y', time.localtime(time.time()))
            return time.strftime('%Y%m%d%H%M%S', time.strptime(now_year + ' ' + line[:15], '%Y %b %d %H:%M:%S'))
        except Exception:
            return '20000101000000'

    def parse_auth_line(self, line: str):
        tmp = line.split(' ')
        if ': Failed password for invalid user' in line:
            return tmp[-4], tmp[-6], '(auth.log) ' + line[16:]
        if ': Failed password for' in line:
            return tmp[-4], tmp[-6], '(auth.log) ' + line[16:]
        if 'Did not receive identification' in line:
            return tmp[-3], '', '(auth.log) ' + line[16:]
        if 'banner exchange' in line and 'invalid format' in line:
            return tmp[-5], '', '(auth.log) ' + line[16:]
        if 'Unable to negotiate' in line and 'diffie-hellman-group-exchange-sha1' in line:
            return tmp[9], '', '(auth.log) ' + line[16:]
        if '(sshd:auth): authentication failure;' in line:
            if ' user=' in line:
                return tmp[-3], tmp[-1], '(auth.log) ' + line[16:]
            return tmp[-1], 'none', '(auth.log) ' + line[16:]
        return None

    def parse_vnc_line(self, line: str):
        if '[AuthFailure]' not in line:
            return None
        tmp = line.split(' ')
        ip = tmp[6].split('::')[0]
        return ip, '', '(vncserver-x11.log) ' + line[30:]

    def parse_kern_line(self, line: str):
        if 'PORT_SCAN_DETECTED:' not in line or ' SRC=' not in line:
            return None
        for token in line.split(' '):
            if token.startswith('SRC='):
                return token.split('=', 1)[1], '', '(kern.log) ' + line
        return None

    def scan_and_compare(self, line: str, source: str) -> bool:
        parsed = None
        if source == 'auth.log':
            parsed = self.parse_auth_line(line)
        elif source == 'vncserver-x11.log':
            parsed = self.parse_vnc_line(line)
        elif source == 'kern.log':
            parsed = self.parse_kern_line(line)

        if parsed is None:
            return False

        check_ip, username, reason = parsed
        if self.check_local_ip(check_ip):
            if self.debugmode:
                print('SAC-local-exempt: ' + check_ip)
            return False

        date_string = self.get_datetime(line, source)
        is_new = self.check_blocklist(check_ip, date_string, reason, user=username)
        if self.debugmode and is_new:
            print('SAC-newblock')
        return is_new

    def save_blocklist(self):
        self.log_data('saving blocklist')
        try:
            with open(self.block_file_name, 'wb') as fblock:
                pickle.dump(self.aBlocklist, fblock)
                fblock.flush()
        except PermissionError:
            self.log_data('ERROR: Permission denied writing to blocklist file: ' + self.block_file_name)
            self.close_gracefully(exitcode=17)
        except OSError as e:
            self.log_data('ERROR: OS error writing to blocklist file: ' + str(e))
            self.close_gracefully(exitcode=17)
        except Exception as e:
            self.log_data('ERROR: Unexpected error writing to blocklist file: ' + str(e))
            self.close_gracefully(exitcode=17)

    def first_run_check_blocklist(self):
        self.log_data('checking blocklist/first run: ' + str(len(self.aBlocklist)) + ' entries')
        for row in self.aBlocklist:
            if len(row.aDateTime) >= self.failcount:
                self.block_ip(row.ip, 'reason: ' + str(len(row.aDateTime)) + ' login failures from this IP')
            else:
                for user in row.aUsername:
                    if self.check_auto_block_users(user):
                        self.block_ip(row.ip, 'bad user: ' + user)
                        break

    def open_blocklist(self):
        self.log_data('opening blocklist')
        if os.path.isfile(self.block_file_name):
            try:
                with open(self.block_file_name, 'rb') as fblock:
                    loaded = pickle.load(fblock)
                self.aBlocklist = self.normalize_loaded_blocklist(loaded)
            except Exception as e:
                print('Exception: ', e)
                self.log_data('blocklist file is corrupt, will be overwritten on save')
                self.aBlocklist = []
        else:
            self.log_data('blocklist file not found, will be created on save')
            self.aBlocklist = []

        self.first_run_check_blocklist()

    def normalize_loaded_blocklist(self, loaded):
        result = []
        if not isinstance(loaded, list):
            return result

        for item in loaded:
            try:
                if isinstance(item, cBlock):
                    result.append(item)
                    continue

                if hasattr(item, 'ip') and hasattr(item, 'aDateTime'):
                    new_item = cBlock(ip=getattr(item, 'ip', None))
                    for dt in list(getattr(item, 'aDateTime', [])):
                        new_item.add_datetime(dt)
                    for reason in list(getattr(item, 'aReason', [])):
                        new_item.add_reason(reason)
                    for username in list(getattr(item, 'aUsername', [])):
                        new_item.add_username(username)
                    result.append(new_item)
            except Exception:
                continue
        return result

    def get_file_inode(self, file_path: str):
        try:
            stat_info = os.stat(file_path)
            return stat_info.st_ino
        except FileNotFoundError:
            return None

    def is_log_rotated(self, original_inode, file_path: str) -> bool:
        current_inode = self.get_file_inode(file_path)
        if current_inode is None:
            self.log_data('File not found while checking inode: ' + file_path)
            return False
        if original_inode != current_inode:
            self.log_data('Log file rotated (inode change: ' + file_path + '): ' + str(original_inode) + ':' + str(current_inode))
            time.sleep(1.5)
            return True
        return False

    def open_auth_stream(self):
        self.auth_pos = 0
        try:
            self.log_data('opening ' + self.auth_file_name)
            self.auth_file_handle = open(self.auth_file_name, 'r')
            self.auth_inode = self.get_file_inode(self.auth_file_name)
            self.auth_exists = True
        except Exception as e:
            self.auth_exists = False
            print('Exception: ', e)
            self.log_data(self.auth_file_name + ' error while loading, exception: ' + str(e))

    def open_vnc_stream(self):
        self.vnc_pos = 0
        self.vnc_exists = False
        if self.vnc_file_name != '':
            try:
                self.log_data('opening ' + self.vnc_file_name)
                self.vnc_file_handle = open(self.vnc_file_name, 'r')
                self.vnc_inode = self.get_file_inode(self.vnc_file_name)
                self.vnc_exists = True
            except Exception as e:
                self.vnc_exists = False
                print('Exception: ', e)
                self.log_data(self.vnc_file_name + ' error while loading, exception: ' + str(e))

    def open_kern_stream(self):
        self.kern_pos = 0
        try:
            self.log_data('opening ' + self.kern_file_name)
            self.kern_file_handle = open(self.kern_file_name, 'r')
            self.kern_inode = self.get_file_inode(self.kern_file_name)
            self.kern_exists = True
        except Exception as e:
            self.kern_exists = False
            print('Exception: ', e)
            self.log_data(self.kern_file_name + ' error while loading, exception: ' + str(e))

    def close_auth_stream(self):
        if self.auth_file_handle is None:
            self.auth_exists = False
            return
        try:
            self.log_data('closing ' + self.auth_file_name)
            self.auth_file_handle.close()
        except Exception as e:
            print('Exception: ', e)
            self.log_data(self.auth_file_name + ' error while closing')
        self.auth_exists = False

    def close_vnc_stream(self):
        if not self.vnc_exists or self.vnc_file_handle is None:
            return
        try:
            self.log_data('closing ' + self.vnc_file_name)
            self.vnc_file_handle.close()
        except Exception as e:
            print('Exception: ', e)
            self.log_data(self.vnc_file_name + ' error while closing')
        self.vnc_exists = False

    def close_kern_stream(self):
        if not self.kern_exists or self.kern_file_handle is None:
            return
        try:
            self.log_data('closing ' + self.kern_file_name)
            self.kern_file_handle.close()
        except Exception as e:
            print('Exception: ', e)
            self.log_data(self.kern_file_name + ' error while closing')
        self.kern_exists = False

    def reopen_log_stream(self, which: str):
        if which == 'auth':
            self.close_auth_stream()
            self.open_auth_stream()
            return
        if which == 'vnc':
            self.close_vnc_stream()
            self.open_vnc_stream()
            return
        if which == 'kern':
            self.close_kern_stream()
            self.open_kern_stream()
            return
        self.log_data('error: ReOpenLogFilesAsStream(), unknown which: ' + which)

    def check_auth_log(self) -> bool:
        if not self.auth_exists or self.auth_file_handle is None:
            return False
        try:
            current_size = os.stat(self.auth_file_name).st_size
        except FileNotFoundError:
            self.auth_exists = False
            return False

        block_status = False
        if current_size > self.auth_pos:
            self.auth_file_handle.seek(self.auth_pos)
            new_data = self.auth_file_handle.read()
            for line in new_data.split('\n'):
                if self.scan_and_compare(line, 'auth.log'):
                    block_status = True
            self.auth_pos = current_size
        return block_status

    def check_vnc_log(self) -> bool:
        if not self.vnc_exists or self.vnc_file_handle is None:
            return False
        try:
            current_size = os.stat(self.vnc_file_name).st_size
        except FileNotFoundError:
            self.vnc_exists = False
            return False

        block_status = False
        if current_size > self.vnc_pos:
            self.vnc_file_handle.seek(self.vnc_pos)
            new_data = self.vnc_file_handle.read()
            for line in new_data.split('\n'):
                if self.scan_and_compare(line, 'vncserver-x11.log'):
                    block_status = True
            self.vnc_pos = current_size
        return block_status

    def check_kern_log(self) -> bool:
        if not self.kern_exists or self.kern_file_handle is None:
            return False
        try:
            current_size = os.stat(self.kern_file_name).st_size
        except FileNotFoundError:
            self.kern_exists = False
            return False

        block_status = False
        if current_size > self.kern_pos:
            self.kern_file_handle.seek(self.kern_pos)
            new_data = self.kern_file_handle.read()
            for line in new_data.split('\n'):
                if self.scan_and_compare(line, 'kern.log'):
                    block_status = True
            self.kern_pos = current_size
        return block_status

    def am_alive(self):
        nowtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        if (nowtime[-5:-3] == '00') and (nowtime[-8:-6] != self.last_checkin_hour):
            self.last_checkin_hour = nowtime[-8:-6]
            self.log_data('Checking in, nothing to report')

    def check_restart_time(self):
        ntime = time.strftime('%H:%M:%S', time.localtime(time.time()))
        if ntime == self.restart_time:
            self.log_data('restarting at ' + ntime)
            if not self.debugmode:
                self.close_gracefully(exitcode=12)
            else:
                print('RESTART/debug mode: restarting at ' + ntime)

    def close_gracefully(self, signal_num=None, frame=None, exitcode: Optional[int] = 0):
        self.log_data('closing...')
        self.log_data('closing streams')

        if self.auth_exists and (exitcode != 10):
            self.close_auth_stream()
        if self.kern_exists and (exitcode != 10):
            self.close_kern_stream()
        if self.vnc_exists and (exitcode != 10):
            self.close_vnc_stream()

        self.save_blocklist()
        self.save_settings()
        self.close_log_file()

        if not self.debugmode:
            self.save_iptables()

        if exitcode is not None:
            self.error_arg(exitcode)

    def run(self):
        signal.signal(signal.SIGINT, self.close_gracefully)
        signal.signal(signal.SIGTERM, self.close_gracefully)

        self.clear_screen()
        self.check_is_linux()

        self.start_dir = os.getcwd().removesuffix(self.slash)
        self.open_log_file()
        self.welcome()
        self.get_args()

        if self.debugmode:
            print('A+') if os.path.isfile(self.auth_file_name) else print('A-')
            print('V+') if os.path.isfile(self.vnc_file_name) else print('V-')
            print('K+') if os.path.isfile(self.kern_file_name) else print('K-')
            self.flush_count = 10

        time.sleep(3)
        self.check_iptables_installed()
        if not self.iptables_available:
            self.log_data('WARNING: iptables not available - IP blocking disabled, but monitoring will continue')

        self.clear_iptables()
        self.open_blocklist()
        self.print_blocklist()

        self.log_data('opening logfiles as stream')

        if not (self.auth_exists or self.kern_exists):
            self.close_gracefully(exitcode=10)

        if self.auth_exists:
            self.open_auth_stream()
        if self.kern_exists:
            self.open_kern_stream()
        #if self.vnc_exists:
        #    self.open_vnc_stream()

        while True:
            self.flush_tick += 1
            if self.flush_tick > self.flush_count:
                self.flush_tick = 0
                self.flush_log_file()
                if self.block_status:
                    if self.debugmode:
                        print('New blocks added to blocklist file')
                    self.save_blocklist()
                    self.block_status = False

            self.check_restart_time()
            self.run_tick += 1
            if self.run_tick >= self.run_every:
                self.run_tick = 0
                self.am_alive()

                if self.auth_exists and self.is_log_rotated(self.auth_inode, self.auth_file_name):
                    self.reopen_log_stream('auth')
                if self.kern_exists and self.is_log_rotated(self.kern_inode, self.kern_file_name):
                    self.reopen_log_stream('kern')
                if self.vnc_exists and self.is_log_rotated(self.vnc_inode, self.vnc_file_name):
                    self.reopen_log_stream('vnc')

                if self.auth_exists:
                    self.auth_blocks = self.check_auth_log()
                if self.kern_exists:
                    self.kern_blocks = self.check_kern_log()
                if self.vnc_exists:
                    self.vnc_blocks = self.check_vnc_log()

                if self.auth_blocks or self.vnc_blocks or self.kern_blocks:
                    self.block_status = True

                if not (self.auth_exists or self.kern_exists):
                    self.close_gracefully(exitcode=10)

            time.sleep(0.25)


def main():
    app = AuthLogger2()
    app.run()


if __name__ == '__main__':
    main()
