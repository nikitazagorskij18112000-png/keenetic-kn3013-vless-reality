"""Exercise the production service's lifecycle offline on a Linux host.

Only its four filesystem paths are changed in a temporary copy. A small fake
BusyBox controls wall time and sleep and operates exclusively on test files and
test processes. A copied Python ELF acts as Xray, so the service's /proc/PID/exe
identity check remains real. These are shell lifecycle tests, not a MIPS/BusyBox
compatibility test, an Xray integration test, or a physical router test.
"""

import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


SERVICE = Path(__file__).resolve().parents[1] / "overlay/usr/libexec/kn3013-xray-service"

_FAKE_XRAY = r'''
import os
from pathlib import Path
import sys
import time

root = Path(os.environ["KN_SERVICE_TEST_ROOT"])
test = "-test" in sys.argv
with (root / "events").open("a") as stream:
    stream.write("preflight\n" if test else "start\n")
if not test:
    while True:
        time.sleep(60)
'''

_FAKE_BUSYBOX = r'''
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root = Path(os.environ["KN_SERVICE_TEST_ROOT"])
state = root / "state"
xray = root / "xray-test"
pidfile = state / "pid"
config = root / "config.json"
command, *args = sys.argv[1:]

def require(condition):
    if not condition:
        raise RuntimeError("Unexpected fake BusyBox operation")

def owns(pid):
    try:
        return Path(f"/proc/{pid}/exe").resolve(strict=True) == xray
    except OSError:
        return False

if command == "date":
    require(args == ["+%s"])
    print((root / "clock").read_text().strip())
elif command == "sleep":
    require(args == ["5"])
    time.sleep(0.03)
elif command == "logger":
    require(len(args) == 3 and args[:2] == ["-t", "kn3013-xray"])
    if args[2] == "Waiting for the router clock before starting Xray.":
        (root / "waiting-notification").touch()
elif command == "mkdir":
    if args == ["-p", str(state)]:
        state.mkdir(exist_ok=True)
    else:
        require(len(args) == 1 and Path(args[0]) in (state / "lock", state / "clock-wait"))
        try:
            Path(args[0]).mkdir()
        except FileExistsError:
            sys.exit(1)
elif command == "rmdir":
    require(len(args) == 1 and Path(args[0]) in (state / "lock", state / "clock-wait"))
    try:
        Path(args[0]).rmdir()
    except OSError:
        sys.exit(1)
elif command == "rm":
    require(len(args) == 2 and args[0] == "-f" and Path(args[1]) in (pidfile, state / "disabled"))
    Path(args[1]).unlink(missing_ok=True)
elif command == "readlink":
    # Only the PID registered by this fixture can ever be inspected or stopped.
    require(len(args) == 1 and pidfile.exists())
    pid = int(pidfile.read_text())
    require(pid > 1 and args == [f"/proc/{pid}/exe"])
    if not owns(pid):
        sys.exit(1)
    print(os.readlink(args[0]))
elif command == "timeout":
    require(args == ["20", str(xray), "run", "-test", "-config", str(config)])
    result = subprocess.run(args[1:], timeout=5, check=False)
    sys.exit(result.returncode)
elif command == "start-stop-daemon":
    if args == ["-S", "-b", "-m", "-p", str(pidfile), "-x", str(xray),
                "--", "run", "-config", str(config)]:
        process = subprocess.Popen([str(xray), "run", "-config", str(config)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        # An append-only registry lets cleanup find every helper even if a bug
        # causes a duplicate launch and overwrites the service PID file.
        with (root / "started-pids").open("a") as stream:
            stream.write(str(process.pid) + "\n")
        pidfile.write_text(str(process.pid) + "\n")
    else:
        require(args == ["-K", "-p", str(pidfile), "-x", str(xray), "-s", "TERM"])
        pid = int(pidfile.read_text())
        require(pid > 1 and owns(pid))
        os.kill(pid, signal.SIGTERM)
else:
    raise RuntimeError("Unsupported fake BusyBox applet")
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "Service lifecycle tests require Linux /proc")
class ServiceTests(unittest.TestCase):
    def setUp(self):
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("A POSIX shell is required")
        self.shell = shell
        self.temporary = tempfile.TemporaryDirectory(prefix="kn3013-service-test-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.children = []
        self.addCleanup(self.cleanup_processes)
        self.state = self.root / "state"
        self.state.mkdir()
        self.clock = self.root / "clock"
        self.clock.write_text("0", encoding="ascii")
        self.events = self.root / "events"
        self.events.write_text("", encoding="ascii")
        self.registry = self.root / "started-pids"
        self.registry.write_text("", encoding="ascii")
        self.config = self.root / "config.json"
        self.config.write_text("{}", encoding="ascii")
        self.xray = self.root / "xray-test"
        # Unlike a shebang script, an ELF copy has the exact /proc/PID/exe path
        # expected by the unmodified running() function in the service.
        shutil.copy2(Path(sys.executable).resolve(), self.xray)
        self.xray.chmod(0o700)
        (self.root / "run").write_text(textwrap.dedent(_FAKE_XRAY), encoding="utf-8")
        self.busybox = self.root / "busybox-test"
        self.busybox.write_text(
            "#!" + str(Path(sys.executable).resolve()) + "\n" + textwrap.dedent(_FAKE_BUSYBOX),
            encoding="utf-8",
        )
        self.busybox.chmod(0o700)
        source = SERVICE.read_text(encoding="utf-8")
        for old, value in (
            ("BB=/bin/busybox", self.busybox),
            ("XRAY=/usr/bin/xray", self.xray),
            ("CONFIG=/etc/xray/config.json", self.config),
            ("STATE=/tmp/kn3013-xray", self.state),
        ):
            self.assertEqual(source.count(old), 1, "The service path declaration changed")
            variable = old.split("=", 1)[0]
            source = source.replace(old, variable + "=" + shlex.quote(str(value)))
        self.script = self.root / "service"
        self.script.write_text(source, encoding="utf-8")
        self.environment = dict(os.environ, KN_SERVICE_TEST_ROOT=str(self.root),
                                PYTHONHOME=sys.base_prefix, PYTHONDONTWRITEBYTECODE="1")
        self.environment.pop("PYTHONPATH", None)

    def cleanup_processes(self):
        # These Popen objects are our own shell sessions. Do not use pkill or
        # enumerate other processes on the computer.
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
        if not self.registry.exists():
            return
        for value in self.registry.read_text(encoding="ascii").splitlines():
            pid = int(value)
            if pid <= 1:
                continue
            try:
                if Path(f"/proc/{pid}/exe").resolve(strict=True) == self.xray:
                    os.kill(pid, signal.SIGTERM)
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        if not self.owns_helper(pid):
                            break
                        time.sleep(0.02)
                    else:
                        if self.owns_helper(pid):
                            os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except FileNotFoundError:
                pass

    def owns_helper(self, pid):
        try:
            return Path(f"/proc/{pid}/exe").resolve(strict=True) == self.xray
        except OSError:
            return False

    def wait_until(self, predicate, message):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.025)
        self.fail(message)

    def action(self, name):
        result = subprocess.run(
            [self.shell, str(self.script), name], cwd=self.root, env=self.environment,
            capture_output=True, text=True, timeout=8,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def start_waiter(self, action="auto"):
        notification = self.root / "waiting-notification"
        notification.unlink(missing_ok=True)
        child = subprocess.Popen(
            [self.shell, str(self.script), action], cwd=self.root, env=self.environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.children.append(child)
        self.wait_until(lambda: (self.state / "clock-wait").is_dir(), "No clock-wait lock")
        # The notification occurs after trap installation, avoiding a race where
        # the signal test terminates the shell between mkdir and its trap command.
        self.wait_until(notification.exists, "Clock waiter did not install its cleanup traps")
        self.assertIsNone(child.poll(), "Clock waiter exited before clock synchronization")
        return child

    def test_epoch_waits_without_starting_xray_and_coalesces_events(self):
        waiter = self.start_waiter()
        self.action("auto")
        self.action("auto")
        self.assertIsNone(waiter.poll())
        self.assertEqual(self.events.read_text(), "", "Even Xray preflight must wait for time")
        self.assertFalse((self.state / "pid").exists())
        self.assertFalse((self.state / "lock").exists())

    def test_clock_correction_starts_once_and_stop_disables_automatic_restart(self):
        waiter = self.start_waiter()
        self.clock.write_text("1795341600", encoding="ascii")
        self.assertEqual(waiter.wait(timeout=8), 0)
        self.wait_until(lambda: self.events.read_text().splitlines() == ["preflight", "start"],
                        "Expected one preflight and one launch")
        self.assertFalse((self.state / "clock-wait").exists())
        pid = int((self.state / "pid").read_text())
        self.assertTrue(self.owns_helper(pid), "PID must belong to this test's Xray executable")
        self.assertIn("Xray running", self.action("status"))
        self.action("auto")
        self.action("auto")
        self.assertEqual(int((self.state / "pid").read_text()), pid)
        self.assertEqual(self.events.read_text().splitlines(), ["preflight", "start"])
        self.action("stop")
        self.wait_until(lambda: not self.owns_helper(pid), "Manual stop did not terminate the test helper")
        self.assertIn("stopped until manual start", self.action("status"))
        self.action("auto")
        self.assertEqual(self.events.read_text().splitlines(), ["preflight", "start"])

    def test_manual_stop_cancels_clock_wait_and_manual_start_can_resume(self):
        waiter = self.start_waiter()
        self.action("stop")
        self.assertEqual(waiter.wait(timeout=8), 0)
        self.assertTrue((self.state / "disabled").is_file())
        self.assertFalse((self.state / "clock-wait").exists())
        self.action("auto")
        self.assertEqual(self.events.read_text(), "")
        restarted = self.start_waiter("start")
        self.assertFalse((self.state / "disabled").exists())
        self.assertEqual(self.events.read_text(), "")
        self.action("stop")
        self.assertEqual(restarted.wait(timeout=8), 0)
        self.assertFalse((self.state / "clock-wait").exists())

    def test_invalid_clock_waits_and_signal_releases_wait_lock(self):
        self.clock.write_text("invalid-clock", encoding="ascii")
        waiter = self.start_waiter("start")
        waiter.terminate()
        self.assertEqual(waiter.wait(timeout=8), 1)
        self.assertFalse((self.state / "clock-wait").exists())
        self.assertEqual(self.events.read_text(), "")


if __name__ == "__main__":
    unittest.main()
