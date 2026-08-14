DIAGNOSTIC COMPANION - USB STICK
================================

WHAT THIS IS
------------
A read-only health check for a Windows or Linux computer. It looks at
disks, memory, network, event logs, battery and drive health, then
explains what it found in plain language.

It does not install anything, change anything, or send anything
anywhere. It reads, and it writes a report file next to itself if you
ask it to.


HOW TO USE IT
-------------
Windows:  double-click RUN-DIAGNOSTIC.bat

Linux:    open a terminal in this folder and run

              ./run-diagnostic.sh

          Linux has no dependable double-click equivalent - most file
          managers open a script in an editor instead of running it -
          so a terminal is the honest answer here.

          If you get "Permission denied", the stick is mounted without
          execute permission. Copy the folder to your home directory
          and run it from there.

A menu appears. Option 1 checks the machine and shows a short summary
that a non-technical person can follow. Option 2 does the same and
saves a full report.


PUTTING AN ICON ON THE DESKTOP
------------------------------
Optional - the launchers above work without it.

Windows:  double-click INSTALL-SHORTCUT.bat
          Adds a Desktop and Start Menu shortcut. To remove them:
          right-click Install-Shortcut.ps1, "Run with PowerShell",
          or run it with  -Remove

Linux:    run  ./install-desktop-entry.sh  from the project folder
          (not from the stick - a desktop entry needs a fixed path,
          and a stick's mount point changes between machines)


THE REPORTS
-----------
Reports are saved into this folder, named after the machine and the
time:

    DESKTOP-ABC_2026-07-20_1142.html

So one stick collects one report per machine, and nothing overwrites
anything. Each report is a single self-contained file - email it, or
open it in any browser on any computer. It needs no internet and no
software installed.

If the stick is write-protected, reports go to your home folder
instead, and the program says so on screen.


ADMINISTRATOR / ROOT
--------------------
Drive health (SMART) needs elevated rights. Without them the program
runs everything else and reports drive health as "could not check" -
it never guesses.

Windows:  right-click RUN-DIAGNOSTIC.bat, "Run as administrator"
Linux:    sudo ./diag


IF WINDOWS WARNS ABOUT THIS PROGRAM
-----------------------------------
It may say "Windows protected your PC" the first time on a new
machine. That is SmartScreen, and it appears because this program is
not code-signed - not because anything is wrong with it.

Click "More info", then "Run anyway".

If you are handing this to a client, it is worth saying that out loud
before it appears rather than after.


TWO VERSIONS ON THE STICK
-------------------------
If this stick has a "onedir" folder as well as diag.exe, that is the
same program in an alternative form. Some corporate machines block
programs that unpack themselves temporarily. If diag.exe is blocked,
try the copy inside the onedir folder instead.


WHAT IT WILL NOT DO
-------------------
It has no repair function. It tells you what it found and what it
would check next; it never changes the machine it is looking at.
That is deliberate - a tool you can run on someone else's computer
without asking permission first is a tool that only reads.
