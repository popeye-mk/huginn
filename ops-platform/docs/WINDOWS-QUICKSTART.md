# Huginn on Windows — the one-page start

Huginn is a quiet watchdog for your network. It watches what is connected,
notices when something changes, and tells you. It never changes your
network and it never guesses — if it could not check something, it says so.

This page gets you running with clicks only. No typing. For everything
else, see the full **MANUAL.md** (and its Glossary if a word is unfamiliar).

---

## 1. Install it — one double-click

1. Copy the **`ops-platform`** folder onto the PC (from the disc, a USB
   stick, or a download).
2. Open **`ops-platform\packaging\windows`**.
3. **Double-click `Install-Huginn.bat`.**
   - If it offers to install **Python**, say **yes** (Huginn needs it).
   - If it offers the optional extras (**nmap**, **numpy**), yes is fine.
   - It does **not** need administrator rights.
   - If it says *"CLOSE this window and run it again"* after installing
     Python, do exactly that — double-click the `.bat` a second time.
4. Done. There is now a **Huginn** icon on your Desktop.

## 2. Open it — click the icon

Double-click **Huginn** on your Desktop. The console opens in your web
browser. (Behind the scenes it starts quietly; nothing new is exposed to
your network.)

## 3. Read the four boxes across the top

They work like a traffic light:

| Dot | Means |
| - | - |
| 🟢 green | checked, and fine |
| 🟠 amber | checked, and it needs you |
| ⚪ grey | could **not** be checked — Huginn does not know |

- **Last patrol** — is the watchdog awake? Grey/"never recorded" on a fresh
  install is normal; click **Check now**.
- **If something happens** — would you actually be told? See step 4.
- **Witnesses** — how many PCs are watching. "1 — this machine only" is
  normal and fine; it just means there is no second PC to cross-check with.
- **Confirmed as yours** — anything unaccounted for. A number like
  "11 unconfirmed" on day one is a **to-do list, not an alarm** — see step 5.

If any box turns amber, click **Check now** and read what it says under each
line: it tells you, in plain words, what to do.

## 4. Get alerts on your phone (5 minutes, worth it)

The desktop pop-up only reaches you while you are at the PC. To be told when
you are away, use the free **ntfy** app:

1. Install **"ntfy"** from your phone's app store.
2. In the app, subscribe to a **topic** — make up a long, secret name
   (treat it like a password; anyone who knows it gets your alerts).
3. In Huginn, click **⚙ Setup → Who gets told**, turn on **ntfy push**, and
   enter the **same topic name**.
4. Click **Save & send test alert** and check the alert reaches your phone.
   If it does not arrive, it is not set up — do not trust it until it does.

## 5. Tell Huginn what is yours (do this once)

Open **⚙ Setup → What's mine**. You will see a list of your devices and
Wi-Fi transmitters. For each one you recognise, click its button to confirm
it. After this, Huginn only flags genuinely **new** things.

- Can't identify a device? Find out what it is **before** confirming it —
  the maker shown next to it is a clue.
- ⚠ For Wi-Fi, confirm each transmitter **you recognise**, not blindly — a
  fake Wi-Fi confirmed by mistake is trusted for good. There is deliberately
  no "confirm everything" button.

## That's it

Huginn now checks your network every hour on its own, and catches up on any
check missed while the PC was off. Leave it be; it will tell you if
something needs you.

**To remove it later:** delete the Desktop icon and the installed folder
(`%LOCALAPPDATA%\Huginn`), and delete the **"Huginn patrol"** task in Task
Scheduler.

---

*Everything here is also in the full MANUAL.md, which covers Linux and
macOS too, all the commands, and how the software is built and tested.*
