# Test sheet — netdiag 0.9.18 on Zorin

Everything new since you last ran it live (you tested 0.9.12; this is 0.9.18).
No Windows needed. One command per line.

Binary: `netdiag_linux_amd64` in this folder — or `netdiag` if you installed it
with `install_linux.sh`.

Roughly 10 minutes, and section 7 is the only one that spends data.

---

## 1. Does this build trust itself? (5 seconds, no network)

```
./netdiag_linux_amd64 selftest
```

Expect **19/19 passed**. If not, stop and send me the output — nothing below
means anything if the reasoning is broken.

---

## 2. The new front page

```
./netdiag_linux_amd64
```

New since you last looked:

- The **first two lines** now answer "is something wrong?" before the wall of
  evidence — a count and the verdict.
- A **What next** block at the bottom naming the two verbs that make sense.

Two things worth checking, because they are the ones I care about:

- If nothing failed, the first line must say **"Nothing failed the checks
  below"** — never "all clear". Absence of a finding is not health.
- **`hosts_file_override` should NOT appear** on a normal Zorin machine.
  That is bug #24: `fe00::0 ip6-localnet` is stock in `/etc/hosts` on every
  Debian-family distro, and until this build the tool reported it as a manual
  override on *every Linux machine alive*. If you still see that finding, check
  `cat /etc/hosts` — if the flagged line is one of the stock `ip6-*` ones, the
  fix did not work and I want to know.

---

## 3. The menu — grouped, and searchable

```
./netdiag_linux_amd64 menu
```

- 20 entries now sit under five headings instead of one numbered wall.
- Type **`print`** instead of a number. It should jump to the printing check.
- Type **`slow`**, then **`ticket`**. Ambiguous words list the candidates.
- Type **`zzz`** — should say nothing matches, not crash.
- `0` backs out of a prompt without dropping you out of the program.

---

## 4. The ticket export (new verb)

```
./netdiag_linux_amd64 ticket
```

Read it as if someone handed it to you cold, and check three things:

1. **RULED OUT** lists the segments measured healthy — this is the section that
   saves the next person from re-testing your LAN.
2. **NOT CHECKED** lists collectors that skipped, each with a reason. On Zorin
   unprivileged you should see `firewall` here.
3. Nothing reads as "all clear" while findings are listed above it.

Then the version that leaves the building:

```
./netdiag_linux_amd64 ticket -anon
```

Hostname must be `redacted-host`, and no public IPs.

```
./netdiag_linux_amd64 ticket slow -o /tmp/case1.txt
```

```
cat /tmp/case1.txt
```

---

## 5. Baselines with history (this is the big new one)

```
./netdiag_linux_amd64 baseline
```

Should name your network in plain terms — *the Wi-Fi network "..."* or *the
network behind gateway 192.168.x.x* — not `unknown-location`.

Run it a second time so there is history:

```
./netdiag_linux_amd64 baseline
```

```
./netdiag_linux_amd64 baseline -list
```

Now compare:

```
./netdiag_linux_amd64 -diff
```

```
./netdiag_linux_amd64 -diff -against 2
```

```
./netdiag_linux_amd64 -diff -against 7d
```

That last one **should fail** with a message naming the oldest snapshot you
actually have. That is deliberate: it never silently substitutes a different
day, because a diff against the wrong baseline looks like evidence.

```
./netdiag_linux_amd64 -diff -against "last tuesday"
```

Should explain the accepted forms rather than just refusing.

**The offer.** Delete the baselines and ask for a diff:

```
rm -rf ~/.local/share/netdiag/baselines ~/.config/netdiag/baselines 2>/dev/null; ./netdiag_linux_amd64 -diff
```

It should now *offer* to save one rather than telling you to go run another
command. Answer `n` first, then run it again and answer `y`.

---

## 6. Change something and watch the diff catch it

This is the real test of the feature. Save a baseline, break something small,
and see whether the diff names it.

```
./netdiag_linux_amd64 baseline
```

Then change your DNS to something different — easiest reversible option:

```
nmcli connection show
```

Note your active connection name, then (replace `NAME`):

```
sudo nmcli connection modify "NAME" ipv4.ignore-auto-dns yes ipv4.dns 1.1.1.1
```

```
sudo nmcli connection up "NAME"
```

```
./netdiag_linux_amd64 -diff
```

The diff should name the resolver change. **Then put it back:**

```
sudo nmcli connection modify "NAME" ipv4.ignore-auto-dns no ipv4.dns ""
```

```
sudo nmcli connection up "NAME"
```

```
./netdiag_linux_amd64 -diff
```

Should be clean again.

---

## 7. `why slow` now names what it cannot see (uses no data by itself)

```
./netdiag_linux_amd64 why slow
```

If the walk found nothing, the last block should say the checks measure an
**idle** link, explain that bufferbloat is invisible to them, and point at
`netdiag speed`. On Wi-Fi it should also mention `why wifi`.

If the walk *did* find something, that block must be **absent** — the offer
must not bury a real finding.

It must only offer. If it starts moving data by itself, that is a serious bug.

---

## 8. Optional — the L2 rules

Only if you have a wired port to plug into. On Wi-Fi, the interesting check is
the negative one:

```
./netdiag_linux_amd64 -json | grep -E "link_primary_is_wireless|link_medium_confirmed|link_speed_mbps"
```

On the laptop over Wi-Fi: `is_wireless` **true**, `medium_confirmed` **true**,
and **no** `link_negotiated_low_wired` finding regardless of the rate. That
rule is for copper only; firing it on Wi-Fi would tell you to replace a cable
you are not using.

---

## What to send back

Anything that surprises you, with the whole console block rather than a
summary. I am most interested in:

1. **Section 2** — whether `hosts_file_override` is gone (bug #24).
2. **Section 6** — whether the diff actually names the change you made.
3. Whether the front page and menu read better than 0.9.12, or just different.

That third one is a judgement call and yours is the one that counts — you are
the person who has to use this on a bad day.
