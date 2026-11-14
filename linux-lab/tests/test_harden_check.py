"""Python entry-point and repair tests. OS commands are fake; writes use temp files."""
import contextlib
import importlib.util
import io
import json
import os
import pty
import re
import select
import shlex
import signal
import time
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'harden_check.py'
SPEC = importlib.util.spec_from_file_location('harden_check', MODULE)
hc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hc)


class FakeSystem(hc.System):
    def __init__(self):
        self.calls = []
        self.enabled = False
        self.is_root = True
        self.is_ubuntu = True
        self.tty = True
        self.fail_enable = False
        self.fail_verify_ssh = False
        self.syntax_calls = 0
        self.rule_added = False
        self.verify_rule = True
        self.ports = '22'
        self.fail_audit = False
        self.marker = None
        self.fail_disable = False
        self.fail_delete = False
        self.extra_rules = []

    def root(self): return self.is_root
    def ubuntu(self): return self.is_ubuntu
    def interactive(self): return self.tty

    def run(self, *args):
        self.calls.append(args)
        code, output = 0, ''
        if args[:2] == ('ss', '-H'):
            output = f'LISTEN 0 128 0.0.0.0:{self.ports} 0.0.0.0:* users:(("sshd",pid=1,fd=3))'
        elif args[:2] == ('systemctl', 'show'): pass
        elif args == ('sshd', '-t'):
            self.syntax_calls += 1
            if self.fail_verify_ssh and self.syntax_calls > 1: code = 1
        elif args[:2] == ('dpkg-query', '-W'): output = 'install ok installed'
        elif args[:2] == ('systemctl', 'cat'): output = '[Timer]'
        elif args[:2] == ('systemctl', 'is-enabled'):
            code, output = (0, 'enabled') if self.enabled else (1, 'disabled')
        elif args[:2] == ('systemctl', 'enable'):
            self.enabled = True
            if self.fail_enable: code = 1
        elif args[:2] == ('systemctl', 'disable'):
            if self.fail_disable: code = 1
            else: self.enabled = False
        elif args == ('ufw', 'status', 'verbose'): output = 'Status: inactive'
        elif args == ('ufw', 'show', 'added'):
            # Real UFW quotes comments: comment 'OS-30:<id>'.
            output = ('ufw allow from 192.0.2.10 to any port 22 proto tcp' + (f" comment '{self.marker}'" if self.marker else '')) if self.rule_added and self.verify_rule else ''
            output += '\n' + '\n'.join(self.extra_rules)
        elif args[:2] == ('ufw', 'allow'):
            # Like UFW's set_rule(), a rule for the same connection with another
            # action or log type is replaced in place instead of kept.
            self.extra_rules = [rule for rule in self.extra_rules if not re.fullmatch(
                r"ufw (deny|reject|limit)( log| log-all)? from 192\.0\.2\.10 to any port 22 proto tcp( comment .*)?", rule)]
            self.rule_added = True
            self.marker = args[-1] if 'comment' in args else None
        elif args[:3] == ('ufw', '--force', 'delete'):
            if self.fail_delete: code = 1
            else: self.rule_added = False
        elif args[0] == 'bash':
            code = 1 if self.fail_audit else 0
            output = ('[WARN] sample: manual review\n[FAIL] ssh.passwordauthentication: yes\n\nSummary: 1 FAIL, 1 WARN\n'
                      if code else '[PASS] sample: good\n\nSummary: 0 FAIL, 0 WARN\n')
        else: raise AssertionError(f'unexpected command: {args}')
        return subprocess.CompletedProcess(args, code, stdout=output, stderr='')


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.system = FakeSystem()
        self.config = self.root / 'sshd_config'
        self.config.write_text('PermitEmptyPasswords no\n')
        self.config.chmod(0o644)
        self.snippets = self.root / 'sshd_config.d'
        self.snippets.mkdir()
        self.rules = (self.root / 'user.rules', self.root / 'user6.rules')
        for rule in self.rules: rule.write_text('# existing rules retained\n')
        for name, value in [('SSH_MAIN', self.config), ('SSH_SNIPPETS', self.snippets), ('UFW_FILES', self.rules),
                            ('BACKUP_UID', os.getuid()), ('BACKUP_GID', os.getgid())]:
            p = patch.object(hc, name, value)
            p.start(); self.addCleanup(p.stop)
        # Temporary directories are user-owned; the production ancestry guard is
        # separately tested below, not disabled in shipped code.
        p = patch.object(hc, 'trusted_parent')
        self.guard = p.start(); self.addCleanup(p.stop)
        self.backups = self.root / 'backups'
        # Production files must be root-owned. Mock that check only for the temp
        # config file, retaining its real metadata for transaction assertions.
        self.original_add = hc.RepairPlan.add_mode
        p = patch.object(hc.RepairPlan, 'add_mode', lambda plan, path, mode, root_owned=False:
                         self.original_add(plan, path, mode, root_owned=False))
        p.start(); self.addCleanup(p.stop)

    def plan(self, fixes=None, **kwargs):
        return hc.RepairPlan(self.system, fixes or ['ssh-permissions'], **kwargs)

    def test_user_key_repair_is_explicit_and_preserves_contents(self):
        directory = self.root / '.ssh'
        directory.mkdir(mode=0o700)
        key = directory / 'authorized_keys'
        key.write_text('ssh-ed25519 TEST-FIXTURE-NOT-A-REAL-KEY\n')
        key.chmod(0o644)
        uid = max(os.getuid(), 1000)
        self.system.account = lambda name: SimpleNamespace(pw_uid=uid, pw_dir=str(self.root))
        original_read = hc.read_file
        def read(path):
            data, state = original_read(path)
            return data, {**state, 'uid': uid} if path == key else state
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)), \
             patch.object(hc, 'read_file', side_effect=read):
            plan = self.plan(['user-key-permissions'], account='student')
        self.assertEqual(plan.desired, {key: 0o600})
        self.assertEqual(key.read_text(), 'ssh-ed25519 TEST-FIXTURE-NOT-A-REAL-KEY\n')
        self.assertEqual(key.stat().st_mode & 0o777, 0o644)

    def test_user_key_repair_refuses_root_and_missing_user(self):
        self.system.account = lambda name: SimpleNamespace(pw_uid=0, pw_dir='/root')
        for name in (None, 'root'):
            with self.subTest(name=name), self.assertRaises(hc.Refused):
                self.plan(['user-key-permissions'], account=name)

    def test_plan_does_not_write(self):
        before = hc.fingerprint(self.config)
        plan = self.plan()
        with contextlib.redirect_stdout(io.StringIO()): plan.preview()
        self.assertEqual(hc.fingerprint(self.config), before)
        self.assertFalse(self.backups.exists())

    def test_snapshot_permission_repair_and_no_reload(self):
        plan = self.plan()
        with contextlib.redirect_stdout(io.StringIO()): backup = plan.execute(self.backups)
        self.assertEqual(hc.fingerprint(self.config)['mode'], 0o600)
        manifest = json.loads((backup / 'manifest.json').read_text())
        self.assertEqual((backup / '0').read_bytes(), self.config.read_bytes())
        self.assertEqual(manifest['files'][0]['mode'], 0o644)
        self.assertEqual((backup / '0').stat().st_mode & 0o777, 0o600)
        self.assertFalse(any('reload' in call or 'restart' in call for call in self.system.calls))

    def test_ssh_postvalidation_failure_restores_permissions(self):
        self.system.fail_verify_ssh = True
        plan = self.plan()
        with self.assertRaisesRegex(hc.Refused, 'rolled back'): plan.execute(self.backups)
        self.assertEqual(hc.fingerprint(self.config)['mode'], 0o644)

    def test_file_drift_prevents_mutation(self):
        plan = self.plan()
        self.config.write_text('changed after preview\n')
        with self.assertRaisesRegex(hc.Refused, 'state changed'): plan.execute(self.backups)
        self.assertFalse(self.backups.exists())
        self.assertEqual(hc.fingerprint(self.config)['mode'], 0o644)

    def test_symlink_refused(self):
        link = self.root / 'linked'
        link.symlink_to(self.config)
        with self.assertRaises(OSError): hc.fingerprint(link)

    def test_hardlink_refused(self):
        os.link(self.config, self.root / 'linked')
        with self.assertRaises(hc.Refused): hc.fingerprint(self.config)

    def test_descriptor_mode_change_rejects_drift(self):
        before = hc.fingerprint(self.config)
        self.config.write_text('changed\n')
        with self.assertRaises(hc.Refused): hc.set_mode(self.config, 0o600, before)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)

    def test_missing_selection_refused(self):
        with self.assertRaises(hc.Refused): hc.RepairPlan(self.system, [])

    def test_already_enabled_timer_noop(self):
        self.system.enabled = True
        plan = self.plan(['unattended-timer'])
        self.assertEqual(plan.steps, [])
        self.assertIsNone(plan.execute(self.backups))
        self.assertFalse(self.backups.exists())

    def test_failed_timer_enable_is_disabled_again(self):
        self.system.fail_enable = True
        plan = self.plan(['ssh-permissions', 'unattended-timer'])
        with self.assertRaisesRegex(hc.Refused, 'rolled back'): plan.execute(self.backups)
        self.assertFalse(self.system.enabled)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)

    def test_timer_enable_never_starts_service(self):
        plan = self.plan(['unattended-timer'])
        with contextlib.redirect_stdout(io.StringIO()): plan.execute(self.backups)
        self.assertTrue(self.system.enabled)
        self.assertFalse(any('--now' in call or 'start' in call for call in self.system.calls))

    def test_forwarded_port_is_rejected(self):
        with self.assertRaisesRegex(hc.Refused, 'real SSH listener'):
            self.plan(['ufw-ssh-rule'], source='192.0.2.10', port=2222)

    def test_broad_or_injected_management_source_refused(self):
        for source in ('0.0.0.0/0', '192.0.2.10; reboot', '0.0.0.0', '224.0.0.1'):
            with self.subTest(source=source), self.assertRaises(hc.Refused):
                self.plan(['ufw-ssh-rule'], source=source, port=22)

    def test_ufw_addition_never_enables_resets_or_deletes(self):
        plan = self.plan(['ufw-ssh-rule'], source='192.0.2.10', port=22)
        before = [path.read_bytes() for path in self.rules]
        with contextlib.redirect_stdout(io.StringIO()): plan.execute(self.backups)
        self.assertTrue(self.system.rule_added)
        self.assertEqual(before, [path.read_bytes() for path in self.rules])
        self.assertFalse(any(call[0] == 'ufw' and call[1] in ('enable', 'reset', 'delete', 'default') for call in self.system.calls))

    def test_ufw_unverified_addition_reports_partial_state(self):
        self.system.verify_rule = False
        plan = self.plan(['ufw-ssh-rule'], source='192.0.2.10', port=22)
        with self.assertRaisesRegex(hc.Refused, 'may have been added'): plan.execute(self.backups)
        self.assertTrue(self.system.rule_added)
        self.assertTrue(list(self.backups.glob('repair-*/manifest.json')))

    def test_listener_drift_refused(self):
        plan = self.plan()
        self.system.ports = '2200'
        with self.assertRaisesRegex(hc.Refused, 'listeners changed'): plan.execute(self.backups)
        self.assertFalse(self.backups.exists())

    # --- UFW classification: plan and apply share ufw_equivalent_allow() ---

    def ufw_plan(self, rules=()):
        self.system = FakeSystem()
        self.system.extra_rules = list(rules)
        return self.plan(['ufw-ssh-rule'], source='192.0.2.10', port=22)

    def no_ufw_mutation(self):
        return not any(c[:2] == ('ufw', 'allow') or c[:3] == ('ufw', '--force', 'delete') for c in self.system.calls)

    def test_same_connection_deny_reject_limit_refused_without_changes(self):
        for rule in ('ufw deny from 192.0.2.10 to any port 22 proto tcp',
                     'ufw reject from 192.0.2.10 to any port 22 proto tcp',
                     'ufw limit from 192.0.2.10 to any port 22 proto tcp',
                     "ufw deny log from 192.0.2.10 to any port 22 proto tcp comment 'admin block'"):
            with self.subTest(rule=rule):
                with self.assertRaisesRegex(hc.Refused, 'would be replaced'):
                    self.ufw_plan([rule])
                self.assertTrue(self.no_ufw_mutation())
                self.assertEqual(self.system.extra_rules, [rule])
                for mode in ('plan', 'apply'):
                    with patch('builtins.input', side_effect=AssertionError('must not prompt')), \
                         contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                        code = hc.main([mode, '--fix', 'ufw-ssh-rule', '--management-source', '192.0.2.10',
                                        '--ssh-port', '22'], self.system)
                    self.assertEqual(code, 2)
                    self.assertIn('would be replaced', err.getvalue())
                self.assertTrue(self.no_ufw_mutation())
        self.assertFalse(self.backups.exists())

    def test_equivalent_allow_rule_is_skip_and_never_touched(self):
        for rule in ("ufw allow from 192.0.2.10 to any port 22 proto tcp comment 'admin rule'",
                     'ufw allow log from 192.0.2.10 to any port 22 proto tcp'):
            with self.subTest(rule=rule):
                plan = self.ufw_plan([rule])
                self.assertEqual(plan.steps, [])
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    plan.preview()
                self.assertIn('[SKIP] ufw-ssh-rule: equivalent allow rule from 192.0.2.10 to port 22/tcp', output.getvalue())
                self.assertIsNone(plan.execute(self.backups))
                with patch('builtins.input', side_effect=AssertionError('must not prompt')), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(hc.main(['apply', '--fix', 'ufw-ssh-rule', '--management-source', '192.0.2.10',
                                              '--ssh-port', '22'], self.system), 0)
                self.assertTrue(self.no_ufw_mutation())
                self.assertEqual(self.system.extra_rules, [rule])
        self.assertFalse(self.backups.exists())

    def test_direction_interface_source_port_and_other_differences_are_distinct(self):
        for rule in ('ufw allow out from 192.0.2.10 to any port 22 proto tcp',
                     'ufw deny out from 192.0.2.10 to any port 22 proto tcp',
                     'ufw allow in on eth1 from 192.0.2.10 to any port 22 proto tcp',
                     'ufw deny in on eth1 from 192.0.2.10 to any port 22 proto tcp',
                     'ufw allow from 192.0.2.10 port 5555 to any port 22 proto tcp',
                     'ufw limit from 192.0.2.10 port 5555 to any port 22 proto tcp',
                     'ufw deny from 192.0.2.10 to any port 22 proto udp',
                     'ufw deny from 192.0.2.11 to any port 22 proto tcp',
                     'ufw route allow from 192.0.2.10 to any port 22 proto tcp',
                     'ufw deny 22/tcp'):
            with self.subTest(rule=rule):
                plan = self.ufw_plan([rule])
                self.assertEqual(len(plan.steps), 1)
                # A fresh root per run: an existing root must be root-owned.
                with contextlib.redirect_stdout(io.StringIO()):
                    backup = plan.execute(self.root / f'backups-{len(list(self.root.glob("backups-*")))}')
                ufw = json.loads((backup / 'manifest.json').read_text())['ufw']
                self.assertEqual(ufw['added_rule'][-2:], ['comment', ufw['marker']])
                self.assertEqual(self.system.extra_rules, [rule])  # appended, never replaced

    def test_rule_fields_follow_ufw_identity(self):
        fields = hc.ufw_rule_fields(shlex.split(
            "ufw deny in on eth0 log from 192.0.2.10 port 5555 to any port 22 proto tcp comment 'a b'"))
        self.assertEqual((fields['action'], fields['in_on'], fields['log'], fields['from'], fields['from_port'],
                          fields['to_port'], fields['proto'], fields['comment']),
                         ('deny', 'eth0', 'log', '192.0.2.10', '5555', '22', 'tcp', 'a b'))
        self.assertTrue(hc.ufw_same_connection(hc.ufw_rule_fields(shlex.split(
            'ufw limit from 192.0.2.10/32 to any port 22 proto tcp')), '192.0.2.10', 22))
        self.assertIsNone(hc.ufw_rule_fields(['ufw', 'allow', 'from', '192.0.2.10', 'unexpected']))

    def test_unclassifiable_rule_naming_the_source_is_refused(self):
        with self.assertRaisesRegex(hc.Refused, 'cannot be classified'):
            self.ufw_plan(['ufw allow from 192.0.2.10 unexpected-token'])
        self.assertTrue(self.no_ufw_mutation())

    def test_apply_rechecks_firewall_immediately_before_rule_addition(self):
        self.system.extra_rules = []
        plan = self.plan(['ssh-permissions', 'ufw-ssh-rule'], source='192.0.2.10', port=22)
        conflict = 'ufw deny from 192.0.2.10 to any port 22 proto tcp'
        original = self.system.run
        def run(*args):
            result = original(*args)
            if args == ('sshd', '-t') and self.system.syntax_calls == 2:
                self.system.extra_rules.append(conflict)  # appears after the chmod
            return result
        with patch.object(self.system, 'run', side_effect=run), \
                self.assertRaisesRegex(hc.Refused, 'firewall changed since preview.*all applied changes rolled back'):
            plan.execute(self.backups)
        self.assertEqual(hc.fingerprint(self.config)['mode'], 0o644)
        self.assertTrue(self.no_ufw_mutation())
        self.assertEqual(self.system.extra_rules, [conflict])
        manifest = json.loads(next(self.backups.glob('repair-*/manifest.json')).read_text())
        self.assertEqual(manifest['status'], 'failed')

    # --- Interruption: deferred SIGINT/SIGTERM/SIGHUP during apply ---

    def forked(self, scenario):
        """Run a real-signal scenario in a child so a missing handler cannot kill the runner."""
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                payload = json.dumps(scenario())
            except BaseException as exc:
                payload = json.dumps({'error': repr(exc)})
            os.write(write_fd, payload.encode())
            os._exit(0)
        os.close(write_fd)
        with os.fdopen(read_fd, 'rb') as stream:
            data = stream.read()
        _, status = os.waitpid(pid, 0)
        self.assertFalse(os.WIFSIGNALED(status), f'child killed by signal {os.WTERMSIG(status) if os.WIFSIGNALED(status) else ""}')
        return json.loads(data)

    def interrupted_apply(self, fixes, trigger, signum, backups, **kwargs):
        plan = self.plan(fixes, **kwargs)
        original = self.system.run
        def run(*args):
            result = original(*args)
            if args[:2] == trigger:
                os.kill(os.getpid(), signum)  # arrives while the command is "running"
            return result
        self.system.run = run
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                plan.execute(backups)
        except hc.Interrupted as exc:
            manifest = json.loads(next(backups.glob('repair-*/manifest.json')).read_text())
            return {'signum': int(exc.signum), 'message': str(exc), 'mode': self.config.stat().st_mode & 0o777,
                    'enabled': self.system.enabled, 'rule_added': self.system.rule_added,
                    'extra_rules': self.system.extra_rules, 'manifest': manifest,
                    'deletes': [list(c) for c in self.system.calls if c[0] == 'ufw' and 'delete' in c]}
        return {'error': 'apply was not interrupted'}

    def test_sigterm_and_sighup_during_apply_revert_and_record_state(self):
        for signum in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=signum.name):
                self.system = FakeSystem()
                backups = self.root / f'backups-{signum.name}'
                result = self.forked(lambda: self.interrupted_apply(
                    ['ssh-permissions', 'unattended-timer'], ('systemctl', 'enable'), signum, backups))
                self.assertNotIn('error', result, result)
                self.assertEqual(result['signum'], signum)
                self.assertEqual(result['mode'], 0o644)
                self.assertFalse(result['enabled'])
                self.assertIn('all applied changes rolled back', result['message'])
                manifest = result['manifest']
                self.assertEqual(manifest['status'], 'interrupted')
                self.assertEqual(manifest['recovery']['signal'], signum.name)
                self.assertEqual(manifest['recovery']['unreverted'], [])
                self.assertEqual(set(manifest['recovery']['reverted']),
                                 {str(self.config), 'apt-daily-upgrade.timer enablement'})
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)

    def test_signal_after_verified_ufw_addition_never_deletes_rule(self):
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=signum.name):
                self.system = FakeSystem()
                self.system.extra_rules = ['ufw allow 443/tcp']
                backups = self.root / f'backups-ufw-{signum.name}'
                result = self.forked(lambda: self.interrupted_apply(
                    ['ufw-ssh-rule'], ('ufw', 'allow'), signum, backups,
                    source='192.0.2.10', port=22))
                self.assertNotIn('error', result, result)
                self.assertTrue(result['rule_added'])
                self.assertEqual(result['extra_rules'], ['ufw allow 443/tcp'])
                self.assertEqual(result['deletes'], [])
                self.assertIsNotNone(result['manifest']['ufw']['added_rule'])
                self.assertEqual(result['manifest']['status'], 'interrupted')
                self.assertEqual(result['manifest']['recovery']['reverted'], [])
                self.assertIn('manually', result['manifest']['recovery']['unreverted'][0])
                self.assertIn(str(backups), result['message'])
                self.assertTrue(list(backups.glob('repair-*/manifest.json')))

    def test_failed_ufw_apply_never_deletes_and_retains_evidence(self):
        for failure in ('command', 'verification', 'after-verification'):
            with self.subTest(failure=failure):
                self.system = FakeSystem()
                self.system.verify_rule = failure != 'verification'
                plan = self.plan(['ufw-ssh-rule'], source='192.0.2.10', port=22)
                original_run = self.system.run
                original_save = hc.save_manifest
                def run(*args):
                    result = original_run(*args)
                    if failure == 'command' and args[:2] == ('ufw', 'allow'):
                        result.returncode = 1  # command mutated before reporting failure
                    return result
                def save(backup, manifest):
                    if failure == 'after-verification' and manifest['status'] == 'applied':
                        raise OSError('simulated final journal failure')
                    original_save(backup, manifest)
                self.system.run = run
                backups = self.root / f'backups-{failure}'
                with patch.object(hc, 'save_manifest', side_effect=save):
                    with self.assertRaises(hc.Refused) as caught:
                        plan.execute(backups)
                self.assertTrue(self.system.rule_added)
                self.assertFalse(any(c[0] == 'ufw' and 'delete' in c for c in self.system.calls))
                manifest_path = next(backups.glob('repair-*/manifest.json'))
                manifest = json.loads(manifest_path.read_text())
                self.assertEqual(manifest['status'], 'failed')
                self.assertIsNotNone(manifest['ufw'])
                self.assertTrue(all((manifest_path.parent / e['backup']).is_file()
                                    for e in manifest['files']))
                self.assertIn('manually', manifest['recovery']['unreverted'][0])
                self.assertIn(str(manifest_path.parent), str(caught.exception))
                if failure == 'after-verification':
                    self.assertIsNotNone(manifest['ufw']['added_rule'])
                    self.assertIsNotNone(manifest['ufw']['after'])

    def test_unverified_ufw_addition_on_signal_is_left_and_recorded(self):
        self.system.verify_rule = False
        result = self.forked(lambda: self.interrupted_apply(
            ['ufw-ssh-rule'], ('ufw', 'allow'), signal.SIGHUP, self.root / 'backups-unverified',
            source='192.0.2.10', port=22))
        self.assertNotIn('error', result, result)
        self.assertTrue(result['rule_added'])
        self.assertEqual(result['deletes'], [])
        self.assertIn('may have been added', result['manifest']['recovery']['unreverted'][0])
        self.assertIn('NOT reverted', result['message'])

    def test_cli_interruption_exit_codes(self):
        for signum, expected in ((signal.SIGINT, 130), (signal.SIGHUP, 129), (signal.SIGTERM, 143)):
            with self.subTest(signal=signum.name):
                with patch('builtins.input', return_value='APPLY OS-30'), \
                     patch.object(hc.RepairPlan, 'execute', side_effect=hc.Interrupted(signum)), \
                     contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(hc.main(['apply', '--fix', 'unattended-timer'], self.system), expected)
                self.assertIn(signum.name, err.getvalue())

    def cli(self, args, answer='APPLY OS-30'):
        with patch('builtins.input', return_value=answer) as prompt, \
             patch.object(hc.RepairPlan, 'execute') as execute, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = hc.main(args, self.system)
        return code, prompt, execute

    def test_plan_cli_has_no_confirmation_or_write(self):
        code, prompt, execute = self.cli(['plan', '--fix', 'unattended-timer'])
        self.assertEqual(code, 0)
        prompt.assert_not_called(); execute.assert_not_called()

    def test_no_tty_refused_before_confirmation(self):
        self.system.tty = False
        code, prompt, execute = self.cli(['apply', '--fix', 'unattended-timer'])
        self.assertEqual(code, 2)
        prompt.assert_not_called(); execute.assert_not_called()

    def test_nonroot_cli_refused(self):
        self.system.is_root = False
        code, prompt, execute = self.cli(['apply', '--fix', 'unattended-timer'])
        self.assertEqual(code, 2)
        prompt.assert_not_called(); execute.assert_not_called()

    def test_nonubuntu_cli_refused(self):
        self.system.is_ubuntu = False
        code, prompt, execute = self.cli(['apply', '--fix', 'unattended-timer'])
        self.assertEqual(code, 2)
        prompt.assert_not_called(); execute.assert_not_called()

    def test_exact_confirmation_required(self):
        for answer in ('yes', 'apply os-30', ' APPLY OS-30 ', ''):
            with self.subTest(answer=answer):
                code, _, execute = self.cli(['apply', '--fix', 'unattended-timer'], answer)
                self.assertEqual(code, 2)
                execute.assert_not_called()

    def test_exact_confirmation_calls_selected_plan(self):
        code, _, execute = self.cli(['apply', '--fix', 'unattended-timer'])
        self.assertEqual(code, 0)
        execute.assert_called_once_with()

    def test_audit_default_and_json_exit_code(self):
        self.system.fail_audit = True
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = hc.main(['--format', 'json'], self.system)
        self.assertEqual(code, 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report['findings'][1]['status'], 'FAIL')
        self.assertEqual(report['exit_code'], 1)
        self.assertEqual((report['complete'], report['error']), (True, None))
        self.assertEqual(report['summary'], {'PASS': 0, 'FAIL': 1, 'WARN': 1, 'SKIP': 0})
        self.assertTrue(any(call[0] == 'bash' and call[2] == 'audit' for call in self.system.calls))

    def test_audit_refuses_repair_options(self):
        code, _, execute = self.cli(['audit', '--fix', 'unattended-timer'])
        self.assertEqual(code, 2)
        self.assertEqual(self.system.calls, [])
        execute.assert_not_called()

    def test_missing_collector_refuses_audit_before_running_commands(self):
        with patch.object(hc, 'SCRIPT_DIR', self.root), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(hc.main(['audit'], self.system), 2)
        self.assertIn('collector hardening.sh is missing or empty', output.getvalue())
        self.assertEqual(self.system.calls, [])

    def test_empty_collector_refuses_audit_before_running_commands(self):
        (self.root / 'hardening.sh').write_text('')
        with patch.object(hc, 'SCRIPT_DIR', self.root), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(hc.main(['audit'], self.system), 2)
        self.assertIn('audit not performed', output.getvalue())
        self.assertEqual(self.system.calls, [])

    def test_collector_with_no_findings_cannot_report_clean_audit(self):
        result = subprocess.CompletedProcess(['bash'], 0, stdout='', stderr='')
        with patch.object(self.system, 'run', return_value=result), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(hc.main(['audit'], self.system), 2)
        self.assertIn('audit incomplete', output.getvalue())

    def audit_output(self, stdout, code, output_format):
        result = subprocess.CompletedProcess(['bash'], code, stdout=stdout, stderr='')
        with patch.object(self.system, 'run', return_value=result), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = hc.main(['audit', '--format', output_format], self.system)
        return status, out.getvalue(), err.getvalue()

    def test_incomplete_or_inconsistent_collector_output_exits_2(self):
        cases = {
            'truncated before summary': ('[WARN] a: b\n[FAIL] c: d\n', 1),
            'summary count mismatch': ('[FAIL] c: d\n\nSummary: 2 FAIL, 0 WARN\n', 1),
            'warning count mismatch': ('[WARN] a: b\n\nSummary: 0 FAIL, 0 WARN\n', 0),
            'summary not last': ('[PASS] a: b\n\nSummary: 0 FAIL, 0 WARN\n[PASS] e: f\n', 0),
            'duplicate summary': ('[PASS] a: b\nSummary: 0 FAIL, 0 WARN\nSummary: 0 FAIL, 0 WARN\n', 0),
            'exit code mismatch': ('[PASS] a: b\n\nSummary: 0 FAIL, 0 WARN\n', 1),
            'unexpected exit': ('[PASS] a: b\n\nSummary: 0 FAIL, 0 WARN\n', 127),
            'killed collector': ('[PASS] a: b\n', -15),
        }
        for name, (stdout, code) in cases.items():
            with self.subTest(case=name):
                status, _, err = self.audit_output(stdout, code, 'text')
                self.assertEqual(status, 2)
                self.assertIn('[FAIL] audit:', err)
                status, out, _ = self.audit_output(stdout, code, 'json')
                report = json.loads(out)
                self.assertEqual((status, report['exit_code'], report['complete']), (2, 2, False))
                self.assertTrue(report['error'])

    def test_json_platform_and_collector_errors_are_valid_json(self):
        self.system.is_ubuntu = False
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(hc.main(['audit', '--format', 'json'], self.system), 2)
        report = json.loads(out.getvalue())
        self.assertEqual((report['exit_code'], report['complete'], report['findings'][0]['check']), (2, False, 'platform'))
        self.system.is_ubuntu = True
        with patch.object(hc, 'SCRIPT_DIR', self.root), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(hc.main(['audit', '--format', 'json'], self.system), 2)
        self.assertIn('missing or empty', json.loads(out.getvalue())['error'])
        self.assertEqual(self.system.calls, [])
        failure = hc.Refused('cannot complete bash; no result inferred')
        with patch.object(self.system, 'run', side_effect=failure), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(hc.main(['audit', '--format', 'json'], self.system), 2)
        report = json.loads(out.getvalue())
        self.assertEqual((report['exit_code'], report['complete'], report['findings']), (2, False, []))
        self.assertIn('cannot complete bash', report['error'])

    def test_non_ubuntu_text_audit_keeps_plain_skip(self):
        self.system.is_ubuntu = False
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(hc.main(['audit'], self.system), 2)
        self.assertEqual(out.getvalue(), '[SKIP] platform: Ubuntu required; no audit or application performed\n')


class TerminalTests(unittest.TestCase):
    def harness(self):
        return (
            "import sys; sys.path.insert(0, " + repr(str(Path(__file__).resolve().parent)) + "); "
            "import test_harden_check as t; s=t.FakeSystem(); "
            "s.interactive=lambda: sys.stdin.isatty() and sys.stdout.isatty(); "
            "t.hc.RepairPlan.execute=lambda self: print('MOCK_REPAIR_EXECUTED'); "
            "sys.exit(t.hc.main(['apply','--fix','unattended-timer'],s))"
        )

    def tty_run(self, answer):
        master, slave = pty.openpty()
        proc = subprocess.Popen([sys.executable, '-c', self.harness()],
                                stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output, sent = b'', False
        deadline = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk: break
                    output += chunk
                    if b'Type exactly ' in output and not sent:
                        os.write(master, (answer + '\n').encode()); sent = True
                if proc.poll() is not None: break
            proc.wait(timeout=2)
        finally:
            if proc.poll() is None: proc.kill(); proc.wait()
            os.close(master)
        return proc.returncode, output.decode()

    def test_real_pty_exact_confirmation_uses_only_fake_repair(self):
        code, output = self.tty_run('APPLY OS-30')
        self.assertEqual(code, 0, output)
        self.assertIn('MOCK_REPAIR_EXECUTED', output)

    def test_real_pty_wrong_confirmation_never_repairs(self):
        code, output = self.tty_run('yes')
        self.assertEqual(code, 2, output)
        self.assertNotIn('MOCK_REPAIR_EXECUTED', output)

    def test_piped_exact_confirmation_is_not_authorization(self):
        result = subprocess.run([sys.executable, '-c', self.harness()],
                                input='APPLY OS-30\n', capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('MOCK_REPAIR_EXECUTED', result.stdout)


class GuardTests(unittest.TestCase):
    def test_untrusted_parent_is_refused(self):
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40777, st_uid=0)):
            with self.assertRaises(hc.Refused): hc.trusted_parent(Path('/etc/ssh/sshd_config'))

    def test_symlink_parent_is_refused(self):
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o120777, st_uid=0)):
            with self.assertRaises(hc.Refused): hc.trusted_parent(Path('/etc/ssh/sshd_config'))


if __name__ == '__main__':
    unittest.main()
