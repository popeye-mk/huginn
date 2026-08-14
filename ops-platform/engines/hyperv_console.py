"""Draining a Hyper-V COM port into a file.

**Why this module exists.** KVM writes a guest's serial console straight
to a file (`--serial file,path=...`), so reading it is reading a file.
Hyper-V does not: `Set-VMComPort` exposes the console as a **named
pipe**, and a pipe carries nothing unless something is listening. With
no reader, `console_log()` finds no file, `guest_console` fails, and
**every Hyper-V boot verification fails forever** — a permanently red
check, which is worse than a missing one because it teaches an operator
to ignore the report.

So a small background process connects to the pipe and copies what it
says into a file. Windows then behaves exactly like Linux, and the
boot checks stay identical on both platforms rather than one proving
less than the other.

## Three details that are easy to get wrong

**1. Hyper-V is the pipe server; we are the client.** `Set-VMComPort
-Path \\\\.\\pipe\\name` makes Hyper-V listen. The reader therefore uses
`NamedPipeClientStream`, not a server stream.

**2. The pipe does not exist until the VM starts.** Connecting during
`create()` fails; the reader is started after `boot()` and retries for a
while, because the exact moment the pipe appears is not ours to know.

**3. The reader must be stopped.** A leaked PowerShell process holding a
pipe open is the Windows equivalent of the orphaned VMs this codebase
already refuses to leave behind. `stop()` is called from `destroy()`,
which itself runs in a `finally`.
"""

import subprocess
from pathlib import Path
from typing import Dict, Optional

# How long the reader waits for the VM to create its pipe. Generous:
# a slow guest on a busy host can take a while to reach the point where
# Hyper-V publishes the COM port, and giving up early would produce an
# empty console file that looks like a silent guest.
CONNECT_ATTEMPTS = 120
CONNECT_INTERVAL_MS = 500

# PowerShell that connects to the pipe and appends every line to a file.
# Written as one script rather than a file on disk so the reader has no
# installation step and nothing to clean up but a process.
_READER = """
$ErrorActionPreference = 'Stop'
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
    '.', '{pipe}', [System.IO.Pipes.PipeDirection]::In)
$connected = $false
for ($i = 0; $i -lt {attempts}; $i++) {{
    try {{ $pipe.Connect(1000); $connected = $true; break }}
    catch {{ Start-Sleep -Milliseconds {interval} }}
}}
if (-not $connected) {{ exit 1 }}
$reader = New-Object System.IO.StreamReader($pipe)
$writer = New-Object System.IO.StreamWriter('{path}', $true)
$writer.AutoFlush = $true
while ($true) {{
    $line = $reader.ReadLine()
    if ($line -eq $null) {{ break }}
    $writer.WriteLine($line)
}}
$writer.Close()
"""


class ConsoleReaders:
    """Background pipe readers, one per guest, started and stopped by name."""

    def __init__(self, powershell: str = "powershell.exe"):
        self.powershell = powershell
        self._processes: Dict[str, subprocess.Popen] = {}

    def start(self, name: str, pipe: str, path: Path) -> Optional[str]:
        """Begin draining `pipe` into `path`. Returns a failure reason or None.

        Never raises. A console we could not capture is reported by the
        check that reads it, as "could not confirm" — turning it into an
        exception here would replace a diagnosis with a crash.
        """
        if name in self._processes:
            return None

        path.parent.mkdir(parents=True, exist_ok=True)
        script = _READER.format(
            pipe=pipe, path=str(path).replace("\\", "\\\\"),
            attempts=CONNECT_ATTEMPTS, interval=CONNECT_INTERVAL_MS,
        )
        try:
            self._processes[name] = subprocess.Popen(
                [self.powershell, "-NoProfile", "-NonInteractive",
                 "-Command", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
        except Exception as exc:  # noqa: BLE001
            return f"{type(exc).__name__}: {exc}"
        return None

    def stop(self, name: str) -> None:
        """Stop the reader for one guest. Safe when there never was one.

        Terminate first, kill if it will not go. A reader blocked on
        `ReadLine()` against a pipe whose VM has vanished will not
        notice politely, and leaving it holding the pipe is exactly the
        leak this module is meant to avoid.
        """
        process = self._processes.pop(name, None)
        if process is None:
            return
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                process.kill()
            except Exception:  # noqa: BLE001
                pass

    def stop_all(self) -> None:
        for name in list(self._processes):
            self.stop(name)

    def is_running(self, name: str) -> bool:
        process = self._processes.get(name)
        return process is not None and process.poll() is None
