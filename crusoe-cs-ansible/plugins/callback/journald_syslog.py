# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Crusoe Cloud Support
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
name: journald_syslog
type: notification
short_description: Send Ansible task events to the local systemd journal
version_added: 1.0.0
description:
  - Sends every Ansible task event (playbook start/end, OK / FAILED /
    SKIPPED / UNREACHABLE task results) to the local systemd journal as
    structured journald records.
  - Writes the native journald datagram protocol directly — no
    python-systemd bindings, no systemd tooling required.
  - The Crusoe Watch Agent (Vector) reads the host's persistent journal
    and forwards every entry to the Crusoe Managed Logs console; filter
    by C(SYSLOG_IDENTIFIER) there to find the events.
  - When the journald socket is absent the plugin disables itself
    silently — stdout output is never affected, and the playbook never
    fails because of logging.
  - This is the Ansible counterpart of the dual-logging pattern used by
    C(crusoe-node-remediation) — stdout + journald, env-gated. Stdout
    remains the primary channel, the journal is the forwardable one.
requirements:
  - The controller (the process running ansible-playbook) must have
    access to a journald socket at I(/run/systemd/journal/socket) —
    either running on a systemd host or with the socket mounted (the
    emudhra-ca DaemonSet chart does exactly that).
options:
  identifier:
    description:
      - Value for the journald C(SYSLOG_IDENTIFIER) field on every event.
    type: str
    default: ansible-command
    env:
      - name: ANSIBLE_JOURNALD_IDENTIFIER
    ini:
      - section: callback_journald_syslog
        key: identifier
  socket_path:
    description:
      - Path to the journald datagram socket. Defaults to the standard
        native socket; override when the socket is mounted elsewhere
        (containers, chroots).
    type: str
    default: /run/systemd/journal/socket
    env:
      - name: ANSIBLE_JOURNALD_SOCKET
    ini:
      - section: callback_journald_syslog
        key: socket_path
notes:
  - This is a notification callback — it runs alongside the stdout
    callback, so enabling it never changes what the operator sees.
  - Enable with C(ANSIBLE_CALLBACKS_ENABLED=journald_syslog) and point
    C(ANSIBLE_CALLBACK_PLUGINS) at this repo's C(plugins/callback) dir.
author:
  - Crusoe Cloud Support
'''

EXAMPLES = r'''
# Inside the emudhra-ca DaemonSet pod (wired by the chart):
#   ANSIBLE_CALLBACKS_ENABLED=journald_syslog
#   ANSIBLE_CALLBACK_PLUGINS=/opt/ansible/plugins/callback
#   ANSIBLE_JOURNALD_IDENTIFIER=emudhra-ca
#   ansible-playbook -i inventory wrapper.yml
'''

import json
import os
import sys

from ansible.parsing.ajson import AnsibleJSONEncoder
from ansible.plugins.callback import CallbackBase

# Shared journald writer. Repo-level module_utils is only merged into the
# ansible.module_utils namespace for module payloads, not controller
# plugins, so import it as a plain module: anchor the plugins dir to this
# file's location (CWD-independent — ansible-playbook may run from
# anywhere).
_PLUGINS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PLUGINS_DIR not in sys.path:
    sys.path.insert(0, _PLUGINS_DIR)
from module_utils.journald import JournalWriter  # noqa: E402


class CallbackModule(CallbackBase):
    """Every task event → one structured journald record."""

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'crusoe.journald_syslog'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._writer = None
        self._identifier = None

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super().set_options(task_keys=task_keys, var_options=var_options, direct=None)
        self._identifier = self.get_option('identifier')
        socket_path = self.get_option('socket_path')
        self._writer = JournalWriter(socket_path=socket_path)
        # Enabled()-style availability probe: if the socket is absent the
        # writer no-ops forever; nothing else changes.
        if self._display.verbosity >= 3:
            self._display.display(
                'journald_syslog: socket %s available=%s'
                % (socket_path, self._writer.available),
                log_only=True)

    def _safe(self, method, *args, **kwargs):
        """Run a journald write, swallowing EVERYTHING.

        Logging must never affect the playbook: an exception that escapes
        a callback method propagates into ansible-core's dispatch and can
        fail the run. The writer already guards its own I/O; this guards
        the callback's own logic (attribute access, JSON encoding) too.
        Failures are surfaced only at -vvv.
        """
        try:
            return method(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 — deliberately broad
            if self._display.verbosity >= 3:
                self._display.display(
                    'journald_syslog: event dropped (%s)' % e,
                    log_only=True)
            return None

    def _emit(self, status, result, priority='info'):
        """Send one task event as a journald record."""
        task = result._task
        host = result._host.get_name()
        action = getattr(task, 'action', '') or ''
        name = task.get_name() or action
        res = result._result if isinstance(result._result, dict) else {}
        # Keep the payload small and useful: the task identity, the status,
        # and the module's own result summary (truncated). Full results
        # remain on stdout; the journal is the searchable index.
        summary = res.get('msg')
        if summary is None:
            summary = 'omitted' if '_ansible_verbose_override' in res else 'see ANSIBLE_RESULT_JSON'
        # Machine-queryable copy of the full result (vault-safe via
        # AnsibleJSONEncoder), truncated. LogsQL can query into it when
        # the pipeline coerces JSON strings to objects.
        result_json = json.dumps(res, cls=AnsibleJSONEncoder)[:2000]
        self._writer.write(
            self._identifier,
            priority,
            'task %s: %s' % (status, name),
            fields={
                'ANSIBLE_HOST': host,
                'ANSIBLE_TASK': name,
                'ANSIBLE_ACTION': action,
                'ANSIBLE_STATUS': status,
                'ANSIBLE_RESULT': str(summary)[:1000],
                'ANSIBLE_RESULT_JSON': result_json,
                'ANSIBLE_CHANGED': str(bool(res.get('changed', False))).lower(),
                'ANSIBLE_FAILED': str(bool(res.get('failed', False)) or status == 'FAILED').lower(),
            },
        )

    def v2_playbook_on_start(self, playbook):
        self._safe(
            self._writer.write,
            self._identifier, 'info',
            'playbook start: %s' % os.path.basename(getattr(playbook, '_file_name', '')),
            fields={'ANSIBLE_STATUS': 'PLAYBOOK_START'})

    def v2_playbook_on_stats(self, stats):
        # One summary record per host: ok/changed/failed/unreachable counts.
        def _recap():
            for host in sorted(stats.processed.keys()):
                s = stats.summarize(host)
                self._writer.write(
                    self._identifier,
                    'err' if (s['failures'] or s['unreachable']) else 'notice',
                    'playbook recap %s: ok=%d changed=%d failed=%d unreachable=%d'
                    % (host, s['ok'], s['changed'], s['failures'], s['unreachable']),
                    fields={
                        'ANSIBLE_STATUS': 'RECAP',
                        'ANSIBLE_HOST': host,
                        'OK': s['ok'], 'CHANGED': s['changed'],
                        'FAILED': s['failures'], 'UNREACHABLE': s['unreachable'],
                    })
        self._safe(_recap)
        # Playbook END event: the counterpart of PLAYBOOK_START. The pod
        # command's own "succeeded; parking" line is printed by the shell
        # AFTER ansible exits, so the callback cannot capture it — this
        # event is the journal-visible equivalent.
        def _end():
            self._writer.write(
                self._identifier, 'notice', 'playbook end',
                fields={'ANSIBLE_STATUS': 'PLAYBOOK_END'})
        self._safe(_end)

    def v2_runner_on_ok(self, result):
        self._safe(self._emit, 'OK', result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._safe(self._emit, 'FAILED', result, priority='err')

    def v2_runner_on_skipped(self, result):
        self._safe(self._emit, 'SKIPPED', result)

    def v2_runner_on_unreachable(self, result):
        self._safe(self._emit, 'UNREACHABLE', result, priority='err')
