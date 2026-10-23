# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Crusoe Cloud Support
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared journald writer — the ONE implementation of the native protocol.

Speaks the systemd journald native protocol directly over its datagram
socket (/run/systemd/journal/socket): each record is a newline-separated
FIELD=value payload sent in a single datagram. No systemd tooling or
python-systemd bindings required on either side.

Used by:
  - plugins/callback/journald_syslog.py  (Ansible task events → journal)
  - any other repo code that needs to emit journal events

The Crusoe Watch Agent (Vector) reads the host's persistent journal and
forwards every entry to the Crusoe Managed Logs console, so records are
searchable there by SYSLOG_IDENTIFIER.

Design notes (mirrors go-systemd's journal.Send semantics, the pattern
used by the node-remediation DaemonSet pattern):
  - availability is checked once (dial the socket) and cached — a missing
    socket means "silently drop", never an error; stdout logging is the
    primary channel and must never be blocked by journald being absent
  - MESSAGE uses the inline/repeated form (MESSAGE=<line> per line).
    The trusted-field encoding (MESSAGE\\n<len>\\n<payload>) is the
    documented multi-line form but journald 255 in containers was
    observed dropping such records entirely; repeated MESSAGE= fields
    are stored as a value list, which every reader handles.
"""

import os
import socket

JOURNAL_SOCKET = '/run/systemd/journal/socket'

# RFC 5424 severity names -> journald PRIORITY numbers.
PRIORITIES = {
    'emerg': 0,
    'alert': 1,
    'crit': 2,
    'err': 3,
    'warning': 4,
    'notice': 5,
    'info': 6,
    'debug': 7,
}


def encode_record(identifier, priority, message, fields=None):
    """Encode one journald native-protocol record as bytes.

    identifier: SYSLOG_IDENTIFIER value (the console filter key).
    priority:   RFC 5424 severity name (see PRIORITIES) or int 0-7.
    message:    payload; newlines become repeated MESSAGE= fields.
    fields:     extra FIELD=value entries; keys are uppercased (journald
                requires uppercase identifiers) and trusted-field names
                (trailing underscore) are rejected.
    """
    if isinstance(priority, str):
        priority = PRIORITIES[priority]
    parts = [
        'PRIORITY=%d' % priority,
        'SYSLOG_IDENTIFIER=%s' % identifier,
        'SYSLOG_FACILITY=3',  # daemon
    ]
    for key in sorted(fields or {}):
        upper = str(key).upper()
        if upper.endswith('_'):
            raise ValueError(
                "journald field '%s' is a trusted field (trailing "
                "underscore) and cannot be set" % key)
        # A literal newline in a value would break the FIELD=value
        # framing (journald would parse the remainder of the datagram
        # as bogus lines). Escape it — journald passes the backslash
        # sequence through as data, and LogsQL readers see \n.
        value = str(fields[key]).replace('\n', '\\n').replace('\r', '')
        parts.append('%s=%s' % (upper, value))
    lines = message.split('\n') or ['']
    for line in lines:
        parts.append('MESSAGE=%s' % line)
    return ('\n'.join(parts) + '\n').encode('utf-8')


class JournalWriter:
    """Write records to the local journald; no-op when it is unavailable.

    Mirrors go-systemd's journal.Enabled() pattern: the socket is probed
    once and the result cached; every subsequent write is a plain datagram
    send with errors swallowed (logging must never break the caller).
    """

    def __init__(self, socket_path=JOURNAL_SOCKET):
        self._socket_path = socket_path
        self._sock = None

    @property
    def available(self):
        """True if the journald socket was reachable at first use."""
        if self._sock is None:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                sock.connect(self._socket_path)
                self._sock = sock
            except OSError:
                self._sock = False
        return self._sock is not False

    def write(self, identifier, priority, message, fields=None):
        """Send one record. Returns True if it reached the socket.

        Never raises: encoding errors (hostile field values) and socket
        failures are both swallowed — logging must never break the caller.
        """
        try:
            if not self.available:
                return False
            record = encode_record(identifier, priority, message, fields)
            self._sock.send(record)
            return True
        except OSError:
            # Socket vanished mid-run — drop silently and re-probe on the
            # next write (the socket may come back, e.g. journald restart).
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            return False
        except Exception:
            # Encoding failure (hostile field/message values) — drop the
            # record, keep the writer usable.
            return False


def writer_from_env(env=None, socket_var='JOURNALD_SOCKET'):
    """Build a JournalWriter, honoring an env-var socket path override.

    Useful for tests and for chroot/container setups where the socket is
    mounted at a non-default path.
    """
    env = env if env is not None else os.environ
    return JournalWriter(socket_path=env.get(socket_var, JOURNAL_SOCKET))
