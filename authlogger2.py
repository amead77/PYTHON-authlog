# Authlogger 1 was 99% written by me. This version is based on v1.0-2026/02/27r13 but is a near complete 
# rewrite with a new codebase and architecture. The prior version is available as authlogger.py for reference,
# but authlogger2.py should be considered a new program with the same general purpose and some shared concepts,
# rather than a direct edit of the prior code. I let GPT-5.3 go mad on this version.
import argparse
import configparser
import datetime
import errno
import fcntl
import ipaddress
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass
from typing import Optional

"""
authlogger2.py - hardened rewrite/replacement for authlogger.py with improved reliability, security, and maintainability.

Primary improvements over prior versions:
- Uses SQLite state store instead of pickle (safer persistence model).
- Strict IP validation via ipaddress module.
- Single-instance lock file to avoid concurrent monitors.
- Robust stream tailing with inode + truncation handling.
- Atomic settings writes to reduce corruption risk.
- Main loop exception guard with traceback logging.
- Dry-run mode (`--dry-run`) as the only CLI option.
- Auto-detects sensible defaults when settings are missing.
"""
#version should now be auto-updated by version_update.py. Do not manually change except the major/minor version. Next comment req. for auto-update
#AUTO-V
version = "v2.1-2026/02/27r18"


@dataclass
class SourceFile:
    name: str
    path: str
    enabled: bool = False
    handle: Optional[object] = None
    inode: Optional[int] = None
    pos: int = 0


class AuthLogger2:
    def __init__(self):
        self.dry_run = False
        self.debugmode = False
        self.cwd = os.getcwd()
        self.start_dir = self.cwd.rstrip('/')
        self.settings_path = os.path.join(self.start_dir, 'settings.ini')

        self.logging_enabled = True
        self.log_path = os.path.join(self.start_dir, 'logs', 'authlogger2.log')
        self.log_handle = None
        self.log_dirty = False
        self.log_rotate_bytes = 10 * 1024 * 1024
        self.log_buffer = {}
        self.log_buffer_interval_seconds = 1.0
        self.log_buffer_last_flush = time.monotonic()

        self.db_path = os.path.join(self.start_dir, 'authlogger2_state.sqlite3')
        self.db = None

        self.local_exemptions = []
        self.autoblock_users = []
        self.failcount = 2
        self.restart_time = 'None'

        self.flush_every_ticks = 80
        self.poll_every_ticks = 4
        self.sleep_seconds = 0.25

        self.tick_flush = 0
        self.tick_poll = 0
        self.last_checkin_hour = ''

        self.auth = SourceFile('auth.log', '')
        self.kern = SourceFile('kern.log', '')
        self.vnc = SourceFile('vncserver-x11.log', '')

        self.active_blocked_ips = set()
        self.iptables_cmd = None
        self.iptables_save_cmd = None
        self.iptables_available = False
        self.iptables_chain = 'AUTHLOGGER_INPUT'
        self.install_scan_rule = True

        self.lock_file_path = os.path.join(self.start_dir, '.authlogger2.lock')
        self.lock_handle = None

        self.pending_state_write = False

    ############################
    # Utility / logging
    ############################
    def now_str(self) -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    def _emit_log_line(self, message: str, repeat_count: int = 1):
        if repeat_count > 1:
            message = f'{message} [{repeat_count}]'
        line = f"[{self.now_str()}]:{message}"
        print(line)
        if self.logging_enabled and self.log_handle is not None:
            self.rotate_log_if_needed()
            self.log_handle.write(line + '\n')
            self.log_dirty = True

    def flush_log_buffer_if_due(self, force: bool = False):
        now = time.monotonic()
        if not force and (now - self.log_buffer_last_flush) < self.log_buffer_interval_seconds:
            return
        if not self.log_buffer:
            self.log_buffer_last_flush = now
            return

        for message, count in self.log_buffer.items():
            self._emit_log_line(message, count)
        self.log_buffer.clear()
        self.log_buffer_last_flush = now

    def log(self, message: str):
        if message in self.log_buffer:
            self.log_buffer[message] += 1
        else:
            self.log_buffer[message] = 1
        self.flush_log_buffer_if_due(force=False)

    def flush_log(self):
        self.flush_log_buffer_if_due(force=True)
        if self.logging_enabled and self.log_handle is not None:
            self.log_handle.flush()
            self.log_dirty = False

    def close_log(self):
        if self.logging_enabled and self.log_handle is not None:
            try:
                self.log('authlogger2 stopped.')
                self.flush_log()
            finally:
                self.log_handle.close()
                self.log_handle = None

    def rotate_log_if_needed(self):
        if not self.logging_enabled or not self.log_path:
            return
        if not os.path.isfile(self.log_path):
            return
        if os.stat(self.log_path).st_size <= self.log_rotate_bytes:
            return

        self.flush_log()
        if self.log_handle is not None:
            self.log_handle.close()
            self.log_handle = None

        old_path = self.log_path + '.old'
        old1_path = self.log_path + '.old.1'
        if os.path.isfile(old_path):
            if os.path.isfile(old1_path):
                os.remove(old1_path)
            os.replace(old_path, old1_path)
        os.replace(self.log_path, old_path)
        self.open_log()

    def open_log(self):
        if not self.logging_enabled:
            print('-- logging to file is off --')
            return
        log_dir = os.path.dirname(self.log_path)
        os.makedirs(log_dir, exist_ok=True)
        self.log_handle = open(self.log_path, 'a', encoding='utf-8')
        self.log(f'authlogger2 started. version: {version}')

    ############################
    # Process lifecycle
    ############################
    def acquire_single_instance_lock(self):
        self.lock_handle = open(self.lock_file_path, 'w')
        try:
            fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_handle.write(str(os.getpid()))
            self.lock_handle.flush()
        except BlockingIOError:
            print('Another authlogger2 instance is already running (lock busy).')
            sys.exit(18)

    def release_single_instance_lock(self):
        if self.lock_handle is None:
            return
        try:
            fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            self.lock_handle.close()
        finally:
            self.lock_handle = None

    def setup_signals(self):
        signal.signal(signal.SIGINT, self.close_gracefully)
        signal.signal(signal.SIGTERM, self.close_gracefully)

    def clear_screen(self):
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')

    def welcome(self):
        print('\n[==-- authlogger2 hardened monitor --==]\n')
        print('Watches auth/kern/vnc logs and blocks hostile IPs via iptables.\n')
        print(f'version: {version}')
        if self.dry_run:
            print('Dry-run mode active: no firewall writes performed.')

    ############################
    # Settings
    ############################
    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--dry-run', action='store_true', help='debug/dry-run mode (no iptables writes)')
        args = parser.parse_args()
        self.dry_run = bool(args.dry_run)
        self.debugmode = self.dry_run

    def check_root_or_enable_debug(self):
        # iptables writes require root privileges. If not root, enforce safe dry-run mode.
        try:
            is_root = (os.geteuid() == 0)
        except AttributeError:
            # Non-POSIX fallback: behave safely.
            is_root = False

        if not is_root:
            self.debugmode = True
            self.dry_run = True
            self.log('Not running as root/sudo; forcing debug dry-run mode (iptables writes disabled).')

    def detect_best_path(self, candidates):
        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return candidates[0] if candidates else ''

    def load_settings(self):
        cfg = configparser.ConfigParser()

        defaults = {
            'localip': '127.0.0.1,192.168.,10.,172.16.',
            'failcount': '3',
            'restart_time': 'None',
            'autoblockusers': 'root,admin,pi,ubuntu,ec2-user,administrator,vncuser,ftp,ftpuser',
            'logging': 'true',
            'blockdb': os.path.join(self.start_dir, 'authlogger2_state.sqlite3'),
            'authfile': self.detect_best_path([
                '/var/log/auth.log',
                os.path.join(self.start_dir, 'auth.log'),
            ]),
            'kernfile': self.detect_best_path([
                '/var/log/kern.log',
                os.path.join(self.start_dir, 'kern.log'),
                os.path.join(self.start_dir, 'kern.log.1'),
            ]),
            'vncfile': self.detect_best_path([
                '/var/log/vncserver-x11.log',
                os.path.join(self.start_dir, 'vncserver-x11.log'),
            ]),
            'poll_ticks': '4',
            'flush_ticks': '80',
            'sleep_seconds': '0.25',
            'install_scan_rule': 'true',
        }

        if os.path.isfile(self.settings_path):
            cfg.read(self.settings_path)

        if 'Settings' not in cfg:
            cfg['Settings'] = {}

        section = cfg['Settings']
        get = lambda key: section.get(key, defaults[key])

        self.local_exemptions = [x.strip() for x in get('localip').split(',') if x.strip()]
        self.autoblock_users = [x.strip().upper() for x in get('autoblockusers').split(',') if x.strip()]

        try:
            self.failcount = max(1, int(get('failcount')))
        except ValueError:
            self.failcount = 3

        self.restart_time = get('restart_time')
        self.logging_enabled = get('logging').lower() in ('1', 'true', 'yes', 'y', 'on')

        self.db_path = get('blockdb')
        self.auth.path = get('authfile')
        self.kern.path = get('kernfile')
        self.vnc.path = get('vncfile')

        try:
            self.poll_every_ticks = max(1, int(get('poll_ticks')))
        except ValueError:
            self.poll_every_ticks = 4

        try:
            self.flush_every_ticks = max(1, int(get('flush_ticks')))
        except ValueError:
            self.flush_every_ticks = 80

        try:
            self.sleep_seconds = max(0.05, float(get('sleep_seconds')))
        except ValueError:
            self.sleep_seconds = 0.25

        self.install_scan_rule = get('install_scan_rule').lower() in ('1', 'true', 'yes', 'y', 'on')

        self.auth.enabled = os.path.isfile(self.auth.path)
        self.kern.enabled = os.path.isfile(self.kern.path)
        self.vnc.enabled = os.path.isfile(self.vnc.path)

        self.log(f'Loaded settings from: {self.settings_path if os.path.isfile(self.settings_path) else "defaults"}')
        self.log(f'Local exemptions: {self.local_exemptions}')
        self.log(f'Autoblock users: {self.autoblock_users}')
        self.log(f'failcount: {self.failcount}')
        self.log(f'restart_time: {self.restart_time}')
        self.log(f'authfile: {self.auth.path} [{"ok" if self.auth.enabled else "missing"}]')
        self.log(f'kernfile: {self.kern.path} [{"ok" if self.kern.enabled else "missing"}]')
        self.log(f'vncfile: {self.vnc.path} [{"ok" if self.vnc.enabled else "missing"}]')

    def save_settings(self):
        cfg = configparser.ConfigParser()
        cfg['Settings'] = {
            'localip': ','.join(self.local_exemptions),
            'failcount': str(self.failcount),
            'restart_time': self.restart_time,
            'autoblockusers': ','.join(self.autoblock_users),
            'logging': 'true' if self.logging_enabled else 'false',
            'blockdb': self.db_path,
            'authfile': self.auth.path,
            'kernfile': self.kern.path,
            'vncfile': self.vnc.path,
            'poll_ticks': str(self.poll_every_ticks),
            'flush_ticks': str(self.flush_every_ticks),
            'sleep_seconds': str(self.sleep_seconds),
            'install_scan_rule': 'true' if self.install_scan_rule else 'false',
        }

        settings_dir = os.path.dirname(self.settings_path) or '.'
        os.makedirs(settings_dir, exist_ok=True)

        fd, temp_path = tempfile.mkstemp(prefix='settings.', suffix='.tmp', dir=settings_dir)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp:
                cfg.write(tmp)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(temp_path, self.settings_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    ############################
    # Database state
    ############################
    def open_db(self):
        db_dir = os.path.dirname(self.db_path) or '.'
        os.makedirs(db_dir, exist_ok=True)

        self.db = sqlite3.connect(self.db_path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS ip_events ('
            'id INTEGER PRIMARY KEY AUTOINCREMENT,'
            'ip TEXT NOT NULL,'
            'event_ts TEXT NOT NULL,'
            'reason TEXT NOT NULL,'
            'username TEXT NOT NULL,'
            'source TEXT NOT NULL'
            ')'
        )
        self.db.execute('CREATE INDEX IF NOT EXISTS idx_events_ip ON ip_events(ip)')
        self.db.execute('CREATE INDEX IF NOT EXISTS idx_events_ts ON ip_events(event_ts)')
        self.db.execute(
            'CREATE UNIQUE INDEX IF NOT EXISTS uniq_event ON ip_events(ip, event_ts, reason, username, source)'
        )
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS blocked_ips ('
            'ip TEXT PRIMARY KEY,'
            'blocked_ts TEXT NOT NULL,'
            'reason TEXT NOT NULL'
            ')'
        )
        self.db.commit()

    def close_db(self):
        if self.db is not None:
            self.db.commit()
            self.db.close()
            self.db = None

    def record_event(self, ip: str, event_ts: str, reason: str, username: str, source: str) -> bool:
        try:
            self.db.execute(
                'INSERT INTO ip_events(ip, event_ts, reason, username, source) VALUES (?, ?, ?, ?, ?)',
                (ip, event_ts, reason, username, source),
            )
            self.pending_state_write = True
            return True
        except sqlite3.IntegrityError:
            return False

    def count_events_for_ip(self, ip: str) -> int:
        cur = self.db.execute('SELECT COUNT(*) FROM ip_events WHERE ip = ?', (ip,))
        return int(cur.fetchone()[0])

    def is_ip_blocked_recorded(self, ip: str) -> bool:
        cur = self.db.execute('SELECT 1 FROM blocked_ips WHERE ip = ? LIMIT 1', (ip,))
        return cur.fetchone() is not None

    def record_blocked_ip(self, ip: str, reason: str):
        self.db.execute(
            'INSERT OR REPLACE INTO blocked_ips(ip, blocked_ts, reason) VALUES (?, ?, ?)',
            (ip, self.now_str(), reason),
        )
        self.pending_state_write = True

    def startup_reapply_blocks(self):
        self.log('Startup: re-evaluating saved events for block decisions')
        cur = self.db.execute('SELECT DISTINCT ip FROM ip_events')
        for (ip,) in cur.fetchall():
            count = self.count_events_for_ip(ip)
            if count >= self.failcount:
                self.block_ip(ip, f'startup failcount reached: {count}')
                continue

            cur2 = self.db.execute('SELECT username FROM ip_events WHERE ip = ?', (ip,))
            for (username,) in cur2.fetchall():
                if self.is_autoblock_user(username):
                    self.block_ip(ip, f'startup autoblock user: {username}')
                    break

    ############################
    # Firewall
    ############################
    def detect_iptables(self):
        self.iptables_cmd = shutil.which('iptables') or '/sbin/iptables'
        if not os.path.isfile(self.iptables_cmd) and shutil.which('iptables') is None:
            self.iptables_available = False
            self.log('iptables not found: monitor-only mode')
            return

        self.iptables_save_cmd = shutil.which('iptables-save') or '/sbin/iptables-save'
        try:
            run = subprocess.run([self.iptables_cmd, '--version'], capture_output=True, timeout=2)
            self.iptables_available = run.returncode == 0
        except Exception as exc:
            self.iptables_available = False
            self.log(f'iptables availability check failed: {exc}')

        if self.iptables_available:
            self.log('iptables detected and usable')
        else:
            self.log('iptables unavailable: monitor-only mode')

    def run_cmd(self, args, timeout=3) -> bool:
        try:
            result = subprocess.run(args, timeout=timeout, capture_output=True, text=True)
            if result.returncode != 0 and self.debugmode:
                self.log(f'Command failed ({result.returncode}): {args} stderr={result.stderr.strip()}')
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.log(f'Command timeout: {args}')
            return False
        except Exception as exc:
            self.log(f'Command error: {args} exc={exc}')
            return False

    def setup_firewall_chain(self):
        if self.dry_run or not self.iptables_available:
            return

        # Create dedicated chain and hook it into INPUT once.
        self.run_cmd([self.iptables_cmd, '-N', self.iptables_chain])
        if not self.run_cmd([self.iptables_cmd, '-C', 'INPUT', '-j', self.iptables_chain]):
            self.run_cmd([self.iptables_cmd, '-I', 'INPUT', '1', '-j', self.iptables_chain])

        # Optional scan log rule (avoid duplicate rule insertion).
        if self.install_scan_rule:
            rule = [
                self.iptables_cmd, '-p', 'tcp', '--syn', '-m', 'state', '--state', 'NEW',
                '-m', 'recent', '--update', '--seconds', '60', '--hitcount', '10',
                '-j', 'LOG', '--log-prefix', 'PORT_SCAN_DETECTED: '
            ]
            if not self.run_cmd([self.iptables_cmd, '-C', 'INPUT'] + rule[1:]):
                self.run_cmd([self.iptables_cmd, '-A', 'INPUT'] + rule[1:])
            set_rule = [
                self.iptables_cmd, '-p', 'tcp', '--syn', '-m', 'state', '--state', 'NEW',
                '-m', 'recent', '--set'
            ]
            if not self.run_cmd([self.iptables_cmd, '-C', 'INPUT'] + set_rule[1:]):
                self.run_cmd([self.iptables_cmd, '-A', 'INPUT'] + set_rule[1:])

    def save_firewall(self):
        if self.dry_run or not self.iptables_available:
            return
        if self.iptables_save_cmd:
            self.run_cmd([self.iptables_save_cmd], timeout=5)

    def flush_iptables_startup(self):
        # Requested startup behavior: clear existing in-memory rules first.
        if self.dry_run:
            self.log('[DRY-RUN] would run: iptables -F')
            return
        if not self.iptables_available:
            self.log('iptables unavailable, cannot flush startup rules')
            return
        if self.run_cmd([self.iptables_cmd, '-F']):
            self.log('Startup firewall flush complete: iptables -F')
        else:
            self.log('Startup firewall flush failed: iptables -F')

    def get_saved_blocked_ips(self):
        cur = self.db.execute('SELECT ip, reason FROM blocked_ips ORDER BY ip ASC')
        return cur.fetchall()

    def restore_saved_blocks_to_firewall(self):
        saved = self.get_saved_blocked_ips()
        self.log(f'Loading saved blocks into firewall ({len(saved)} total)...')

        restored = 0
        failed = 0
        skipped = 0

        for ip, reason in saved:
            self.active_blocked_ips.add(ip)

            if self.dry_run:
                restored += 1
                continue

            if not self.iptables_available:
                failed += 1
                continue

            if self.run_cmd([self.iptables_cmd, '-C', self.iptables_chain, '-s', ip, '-j', 'DROP']):
                skipped += 1
                continue

            if self.run_cmd([self.iptables_cmd, '-A', self.iptables_chain, '-s', ip, '-j', 'DROP']):
                restored += 1
            else:
                failed += 1

        if self.dry_run:
            self.log(
                f'[DRY-RUN] startup block restore summary: '
                f'would_restore={restored}, failed={failed}, skipped={skipped}'
            )
        else:
            self.log(
                f'startup block restore summary: '
                f'restored={restored}, failed={failed}, skipped={skipped}'
            )

    def block_ip(self, ip: str, reason: str):
        if ip in self.active_blocked_ips or self.is_ip_blocked_recorded(ip):
            return

        self.active_blocked_ips.add(ip)
        self.record_blocked_ip(ip, reason)

        if self.dry_run:
            self.log(f'[DRY-RUN] block {ip} reason: {reason}')
            return

        if not self.iptables_available:
            self.log(f'iptables unavailable, cannot block {ip}; reason: {reason}')
            return

        # Avoid duplicate drop rule in dedicated chain.
        if self.run_cmd([self.iptables_cmd, '-C', self.iptables_chain, '-s', ip, '-j', 'DROP']):
            return

        if self.run_cmd([self.iptables_cmd, '-A', self.iptables_chain, '-s', ip, '-j', 'DROP']):
            self.log(f'Blocked IP {ip} ({reason})')
        else:
            self.log(f'Failed to apply block for {ip}')

    ############################
    # Parsing and policy
    ############################
    def parse_event_ts(self, line: str, source_name: str) -> str:
        # ISO first token format (auth/kern modern logs)
        try:
            first = line.split()[0]
            if 'T' in first:
                # fromisoformat doesn't always accept trailing Z.
                first = first.replace('Z', '+00:00')
                dt = datetime.datetime.fromisoformat(first)
                return dt.strftime('%Y%m%d%H%M%S')
        except Exception:
            pass

        # VNC style where second token is ISO timestamp
        if source_name == 'vncserver-x11.log':
            try:
                second = line.split()[1].replace('Z', '+00:00')
                dt = datetime.datetime.fromisoformat(second)
                return dt.strftime('%Y%m%d%H%M%S')
            except Exception:
                pass

        # Legacy syslog fallback: "Jun 28 03:26:42 ..."
        try:
            year = time.strftime('%Y', time.localtime())
            dt = time.strptime(f'{year} {line[:15]}', '%Y %b %d %H:%M:%S')
            return time.strftime('%Y%m%d%H%M%S', dt)
        except Exception:
            return '20000101000000'

    def normalize_ip(self, candidate: str) -> Optional[str]:
        try:
            return str(ipaddress.ip_address(candidate))
        except Exception:
            return None

    def is_exempt_ip(self, ip: str) -> bool:
        for token in self.local_exemptions:
            token = token.strip()
            if not token:
                continue
            if '/' in token:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(token, strict=False):
                        return True
                except Exception:
                    continue
            elif token.endswith('.'):
                if ip.startswith(token):
                    return True
            else:
                if ip == token:
                    return True
        return False

    def is_autoblock_user(self, username: str) -> bool:
        if not username:
            return False
        return username.strip().upper() in self.autoblock_users

    def parse_auth_line(self, line: str):
        words = line.split()

        if ': Failed password for invalid user' in line and ' from ' in line:
            try:
                idx_from = words.index('from')
                idx_user = words.index('user') + 1
                ip = self.normalize_ip(words[idx_from + 1])
                username = words[idx_user]
                return ip, username, '(auth.log) ' + line
            except Exception:
                return None

        if ': Failed password for' in line and ' from ' in line:
            try:
                idx_from = words.index('from')
                idx_for = words.index('for') + 1
                username = words[idx_for]
                if username == 'invalid':
                    username = words[idx_for + 2]
                ip = self.normalize_ip(words[idx_from + 1])
                return ip, username, '(auth.log) ' + line
            except Exception:
                return None

        if 'Did not receive identification' in line and ' from ' in line:
            try:
                idx = words.index('from')
                ip = self.normalize_ip(words[idx + 1])
                return ip, '', '(auth.log) ' + line
            except Exception:
                return None

        if 'banner exchange' in line and 'invalid format' in line and ' from ' in line:
            try:
                idx = words.index('from')
                ip = self.normalize_ip(words[idx + 1])
                return ip, '', '(auth.log) ' + line
            except Exception:
                return None

        if 'Unable to negotiate with' in line and ' port ' in line:
            try:
                idx = words.index('with')
                ip = self.normalize_ip(words[idx + 1])
                return ip, '', '(auth.log) ' + line
            except Exception:
                return None

        if '(sshd:auth): authentication failure;' in line:
            found_ip = None
            found_user = 'none'
            for word in words:
                if word.startswith('rhost='):
                    found_ip = self.normalize_ip(word.split('=', 1)[1])
                elif word.startswith('user='):
                    user = word.split('=', 1)[1].strip()
                    if user:
                        found_user = user
            if found_ip:
                return found_ip, found_user, '(auth.log) ' + line

        return None

    def parse_kern_line(self, line: str):
        if 'PORT_SCAN_DETECTED:' not in line or 'SRC=' not in line:
            return None
        for word in line.split():
            if word.startswith('SRC='):
                ip = self.normalize_ip(word.split('=', 1)[1])
                if ip:
                    return ip, '', '(kern.log) ' + line
        return None

    def parse_vnc_line(self, line: str):
        if '[AuthFailure]' not in line:
            return None
        words = line.split()
        for word in words:
            if '::' in word and '.' in word:
                maybe_ip = word.split('::', 1)[0].strip(':')
                ip = self.normalize_ip(maybe_ip)
                if ip:
                    return ip, '', '(vncserver-x11.log) ' + line
        return None

    def parse_line(self, source_name: str, line: str):
        if source_name == 'auth.log':
            return self.parse_auth_line(line)
        if source_name == 'kern.log':
            return self.parse_kern_line(line)
        if source_name == 'vncserver-x11.log':
            return self.parse_vnc_line(line)
        return None

    def process_line(self, source: SourceFile, line: str):
        parsed = self.parse_line(source.name, line)
        if not parsed:
            return False

        ip, username, reason = parsed
        if not ip:
            return False

        if self.is_exempt_ip(ip):
            if self.debugmode:
                self.log(f'exempt ip skipped: {ip}')
            return False

        event_ts = self.parse_event_ts(line, source.name)
        inserted = self.record_event(ip, event_ts, reason, username, source.name)
        if not inserted:
            return False

        if self.is_autoblock_user(username):
            self.block_ip(ip, f'autoblock user: {username}')
            return True

        count = self.count_events_for_ip(ip)
        if count >= self.failcount:
            self.block_ip(ip, f'failcount reached: {count}')
            return True

        return True

    ############################
    # Stream read / rotation
    ############################
    def get_inode(self, path: str) -> Optional[int]:
        try:
            return os.stat(path).st_ino
        except FileNotFoundError:
            return None

    def open_source(self, source: SourceFile):
        source.enabled = os.path.isfile(source.path)
        if not source.enabled:
            source.handle = None
            source.inode = None
            source.pos = 0
            return

        source.handle = open(source.path, 'r', encoding='utf-8', errors='replace')
        source.inode = self.get_inode(source.path)
        source.pos = os.stat(source.path).st_size
        source.handle.seek(source.pos)
        self.log(f'opened stream: {source.path} pos={source.pos}')

    def backfill_source_history(self, source: SourceFile):
        if not source.enabled:
            return 0, 0, 0

        total_lines = 0
        matched_events = 0
        imported_events = 0
        try:
            with open(source.path, 'r', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    total_lines += 1
                    line = line.rstrip('\n')
                    if self.parse_line(source.name, line):
                        matched_events += 1
                    if self.process_line(source, line):
                        imported_events += 1
        except Exception as exc:
            self.log(f'backfill error on {source.path}: {exc}')
        return total_lines, matched_events, imported_events

    def backfill_existing_logs_if_dry_run(self):
        if not self.dry_run:
            return

        self.log('Dry-run startup backfill enabled: scanning existing log contents from beginning')
        total_lines = 0
        total_matches = 0
        total_events = 0
        for source in (self.auth, self.kern, self.vnc):
            lines, matches, events = self.backfill_source_history(source)
            total_lines += lines
            total_matches += matches
            total_events += events
            if source.enabled:
                self.log(
                    f'backfill summary [{source.name}]: '
                    f'lines={lines}, matched_events={matches}, imported_events={events}'
                )

        self.log(
            f'backfill complete: lines={total_lines}, '
            f'matched_events={total_matches}, imported_events={total_events}'
        )

    def close_source(self, source: SourceFile):
        if source.handle is not None:
            try:
                source.handle.close()
            except Exception:
                pass
        source.handle = None

    def reopen_source(self, source: SourceFile):
        self.close_source(source)
        self.open_source(source)

    def check_rotation_or_truncation(self, source: SourceFile):
        if not source.enabled:
            return

        if not os.path.isfile(source.path):
            source.enabled = False
            self.close_source(source)
            self.log(f'source disappeared: {source.path}')
            return

        try:
            stat_info = os.stat(source.path)
        except FileNotFoundError:
            source.enabled = False
            self.close_source(source)
            return

        current_inode = stat_info.st_ino
        current_size = stat_info.st_size

        if source.inode != current_inode:
            self.log(f'rotation detected (inode): {source.path}')
            self.reopen_source(source)
            return

        if current_size < source.pos:
            self.log(f'truncation detected: {source.path}')
            source.pos = 0
            if source.handle is not None:
                source.handle.seek(0)

    def read_new_lines(self, source: SourceFile) -> bool:
        if not source.enabled or source.handle is None:
            return False

        changed = False
        source.handle.seek(source.pos)
        new_data = source.handle.read()
        if not new_data:
            return False

        source.pos = source.handle.tell()
        for line in new_data.splitlines():
            if self.process_line(source, line):
                changed = True
        return changed

    ############################
    # Runtime checks
    ############################
    def check_restart_time(self):
        if not self.restart_time or self.restart_time.lower() == 'none':
            return
        now_time = time.strftime('%H:%M:%S', time.localtime())
        if now_time == self.restart_time:
            self.log(f'restart time reached: {now_time}')
            self.close_gracefully(exitcode=12)

    def am_alive(self):
        nowtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        if (nowtime[-5:-3] == '00') and (nowtime[-8:-6] != self.last_checkin_hour):
            self.last_checkin_hour = nowtime[-8:-6]
            self.log('Checking in, nothing to report')

    def commit_state_if_needed(self):
        if self.pending_state_write and self.db is not None:
            self.db.commit()
            self.pending_state_write = False

    ############################
    # Shutdown / error
    ############################
    def close_gracefully(self, signal_num=None, frame=None, exitcode=0):
        try:
            self.log('closing...')
            self.close_source(self.auth)
            self.close_source(self.kern)
            self.close_source(self.vnc)
            self.commit_state_if_needed()
            self.save_settings()
            self.save_firewall()
            self.close_db()
            self.close_log()
        finally:
            self.release_single_instance_lock()

        if exitcode is not None:
            sys.exit(exitcode)

    ############################
    # Startup and main loop
    ############################
    def setup(self):
        self.parse_args()
        self.clear_screen()
        self.acquire_single_instance_lock()
        self.open_log()
        self.welcome()
        self.setup_signals()
        self.check_root_or_enable_debug()

        self.load_settings()
        self.open_db()

        self.detect_iptables()

        # Requested startup behavior: reset firewall rules, then rebuild from saved blocklist.
        self.flush_iptables_startup()
        self.setup_firewall_chain()
        self.restore_saved_blocks_to_firewall()

        self.open_source(self.auth)
        self.open_source(self.kern)
        self.open_source(self.vnc)

        if not (self.auth.enabled or self.kern.enabled or self.vnc.enabled):
            self.log('No log sources available. Exiting.')
            self.close_gracefully(exitcode=10)

        self.backfill_existing_logs_if_dry_run()
        self.startup_reapply_blocks()
        self.commit_state_if_needed()

    def run_loop(self):
        while True:
            try:
                self.tick_flush += 1
                if self.tick_flush >= self.flush_every_ticks:
                    self.tick_flush = 0
                    self.flush_log()
                    self.commit_state_if_needed()

                self.check_restart_time()

                self.tick_poll += 1
                if self.tick_poll >= self.poll_every_ticks:
                    self.tick_poll = 0
                    self.am_alive()

                    for source in (self.auth, self.kern, self.vnc):
                        if source.enabled:
                            self.check_rotation_or_truncation(source)
                            self.read_new_lines(source)

                    if not (self.auth.enabled or self.kern.enabled or self.vnc.enabled):
                        self.log('All sources unavailable. Exiting.')
                        self.close_gracefully(exitcode=10)

                time.sleep(self.sleep_seconds)

            except SystemExit:
                raise
            except Exception:
                self.log('Unhandled exception in main loop:')
                self.log(traceback.format_exc())
                self.commit_state_if_needed()
                time.sleep(1.0)

    def run(self):
        self.setup()
        self.run_loop()


def main():
    app = AuthLogger2()
    app.run()


if __name__ == '__main__':
    main()
