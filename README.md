# Concurrent File Sharing System with SDN

A multi-user file-sharing service built on raw **TCP sockets** (Python `socket` + `threading`),
run inside **Mininet** with an **Open vSwitch** switch controlled by an **OS-Ken** (OpenFlow 1.3)
controller. The application reports security events to the controller, which reacts by installing
and removing flow rules; the controller also monitors bandwidth and can rate-limit a host that
monopolises the link.

## Architecture

```text
                  +------------------------+
                  |  OS-Ken controller c0  |   reads events.jsonl, installs flows,
                  |  (127.0.0.1:6653)      |   logs bandwidth to stats.csv
                  +-----------+------------+
                              | OpenFlow 1.3
                        +-----+-----+
                        |    s1     |   Open vSwitch
                        +-+--+--+-+-+
        port 1 |  port 2 | port 3|  | port 4 (capped, default 10 Mbit/s)
              h1        h2      h3  server 10.0.0.4 : TCP 5000
          10.0.0.1  10.0.0.2  10.0.0.3
```

All four hosts connect only to `s1` (star topology).

**Socket -> SDN integration.** The file server appends one JSON line per application event
(`AUTH_OK`, `AUTH_FAIL`, `UPLOAD`, `DOWNLOAD`, ...) to `events.jsonl`. Mininet hosts share the
filesystem with the controller process, so the controller simply tails that file.

* **Dynamic blocking.** After **3 failed logins from one IP** the controller installs a priority-200
  DROP flow for `IP -> 10.0.0.4:5000` with a 30 s hard timeout; access is restored automatically.
* **Bandwidth monitoring.** Port statistics every 2 s -> `stats.csv` (per-port Mbit/s).
* **Hog limiter (optional, `HOG_LIMIT=1`).** If one client takes more than 70% of a busy link while
  another client is active (two consecutive polls), the controller attaches an OpenFlow meter
  (50% of the link) to that host's download traffic for 20 s. It re-checks after expiry.

## Files

| File | Purpose |
|---|---|
| `server.py` | Threaded TCP file server: authentication, LIST, UPLOAD, DOWNLOAD, metadata, event log |
| `fsclient.py` | Client library implementing the protocol |
| `client.py` | Interactive command-line client |
| `webapp.py` | CampusShare portal: roles, assignments, materials, grading, browser UI, live SDN panel |
| `controller.py` | OS-Ken controller: learning switch, dynamic blocking, bandwidth monitor, hog limiter |
| `policy.py` | Pure-Python policies: `BlockPolicy` (3 failures / 60 s) and `HogPolicy` |
| `topology.py` | Mininet topology; `--mode sdn` or `--mode baseline`, link cap options, `--web` gateway |
| `bench.py`, `analyze.py` | Benchmark client and results summariser |
| `exp_sdn.mn`, `exp_baseline.mn` | Access-control / throughput experiments (run from the Mininet CLI) |
| `exp_hog_nolimit.mn`, `exp_hog_limit.mn` | Hog-limiter experiment, limiter off / on |
| `selftest.py` | Local loopback tests of the server (no Mininet needed) |
| `results.csv`, `results_summary.md` | Raw and summarised experiment results |

## CampusShare portal (the application)

The file-sharing system is used inside a real-life application: **CampusShare**, a college
assignment-submission and course-material portal. `webapp.py` is the application layer (a
standard-library HTTP server plus a browser interface). The files themselves live on the TCP
file server; every upload and download is an ordinary **TCP connection** made with `fsclient.py`,
so it crosses the Open vSwitch and is subject to the controller's policies.

```text
 Browser --HTTP--> webapp.py (roles, courses, assignments, grades, portal.json)
                      |  TCP :5000 (fsclient.py), via switch port 5 (10.0.0.254)
                      v
                    s1 (Open vSwitch) <--OpenFlow-- OS-Ken controller (block / limit / monitor)
                      |
                    file server 10.0.0.4 (server.py)
```

| Role | Demo account | Can do |
|---|---|---|
| Student | alice / alice123, bob / bob123, carol / carol123 | see assignments, submit and resubmit work, see own marks and feedback, download course materials |
| Faculty | prof / prof123 | publish assignments with due dates, upload course materials, download every submission, grade with feedback |
| Admin | admin / 1234 | everything faculty can do |

How the application uses the file service:

* Submissions are stored on the file server as `SUB_<assignment>_<student>_<file>`, course
  materials as `MAT_<course>_<file>`. Late submissions (after the due date) are flagged.
* **Access rules** (enforced by the portal on every download): a student can download only their own
  submissions and course materials; faculty and admin can download any submission; files not created
  by the portal are not reachable through it. A new submission clears an old grade.
* Assignments, submission records and grades are kept in `portal.json` (written atomically under a lock).
* The right-hand panel shows live switch-port traffic (`stats.csv`) and policy events
  (`controller_events.log`) from the controller.

Start the network with `--web`, which attaches this computer to the switch as `10.0.0.254` (port 5),
so the portal's traffic really crosses the switch and the controller's policies:

```bash
# Terminal A: controller            HOG_LIMIT=1 osken-manager controller.py
# Terminal B: network               sudo mn -c ; sudo python3 topology.py --web
#   mininet>  server python3 server.py > server.log 2>&1 &
# Terminal C: portal (normal user)  python3 webapp.py
```

Open <http://localhost:8080>. Three wrong passwords in the login form trigger the same dynamic
block (the portal gateway, 10.0.0.254, is blocked for 30 s; the page explains it and the controller
panel shows `BLOCK` and `UNBLOCK`). Without Mininet: run the file server locally with
`--host 127.0.0.1` and start `python3 webapp.py --server-host 127.0.0.1`.

Security notes: sessions are kept in server memory (cookie `HttpOnly`, `SameSite=Strict`); file names
are sanitised to `[A-Za-z0-9._-]`; the portal listens on `127.0.0.1` only; traffic is plain HTTP, fine
for a local demo only. The portal's access rules apply to the web interface; the raw file server
itself still lets any authenticated user list and download any file through the command-line client.

## Protocol

Every control message is one UTF-8 line ending in `\n`; file bytes follow an exact size.

```text
C: AUTH <user> <password>     S: OK | ERR <reason>       (3 failures close the connection)
C: LIST                       S: OK <nbytes>\n<nbytes of text>
C: UPLOAD <name> <size>       S: READY | ERR ...   then <size> raw bytes   S: OK | ERR ...
C: DOWNLOAD <name>            S: OK <size>\n<size raw bytes> | ERR file not found
C: QUIT                       S: BYE
```

Safety properties: file names are restricted to `[A-Za-z0-9._-]` (no paths, no `..`); uploads go
to a temporary `.part` file that is removed if the transfer is interrupted; `metadata.json`
writes are locked and atomic.

Demo accounts (hard-coded, passwords stored as salted PBKDF2 hashes in memory):
`admin/1234`, `alice/alice123`, `bob/bob123`, `carol/carol123`, `prof/prof123`. Traffic is not encrypted (no TLS).

## Requirements

Ubuntu 24.04 (WSL2 works), Python 3.12, Mininet 2.3.0, Open vSwitch, OS-Ken
(`sudo apt install mininet python3-os-ken`). If Mininet cannot start Open vSwitch after a
WSL restart: `sudo service openvswitch-switch start`.

## Quick check without Mininet

```bash
python3 selftest.py        # 13 checks: 5 MB hash, path traversal, interrupted upload, 8 parallel clients ...
```

## Running the SDN demo

Terminal A (controller; add `HOG_LIMIT=1` to enable the limiter):

```bash
cd file-sharing-sdn
osken-manager controller.py
```

Terminal B (network):

```bash
cd file-sharing-sdn
sudo mn -c
sudo python3 topology.py            # sdn mode, server link 10 Mbit/s
```

At the `mininet>` prompt:

```text
pingall
server python3 server.py > server.log 2>&1 &
h2 sh -c 'printf "LIST\nQUIT\n" | python3 client.py --host 10.0.0.4 --user admin --password 1234'
```

Dynamic block demo (h3 fails three logins, is blocked, then recovers after 30 s):

```text
h3 sh -c 'for i in 1 2 3; do python3 client.py --host 10.0.0.4 --user admin --password wrong; done'
h3 sh -c 'printf "LIST\nQUIT\n" | timeout 5 python3 client.py --host 10.0.0.4 --user admin --password 1234'   # no output: blocked
h2 sh -c 'printf "LIST\nQUIT\n" | python3 client.py --host 10.0.0.4 --user admin --password 1234'             # still works
sh ovs-ofctl -O OpenFlow13 dump-flows s1                                                                      # priority-200 drop flow
sh cat controller_events.log                                                                                  # BLOCK ... response_ms=..., UNBLOCK ...
```

Note: the Mininet prompt replaces host names such as `h2` with their IPs inside commands, and
several background (`&`) commands sent to the same host can get garbled, so start multiple
background jobs from one `sh -c '... & ... & wait'` command (as `exp_hog_*.mn` do).

## Reproducing the experiments

SDN run (controller running, `topology.py` in sdn mode, server started as above):

```text
source exp_sdn.mn
```

Baseline run: stop the controller, `sudo mn -c`, `sudo python3 topology.py --mode baseline`,
start the server, then `source exp_baseline.mn`.

Hog-limiter run: start the controller once with `HOG_LIMIT=0` and `source exp_hog_nolimit.mn`,
then restart it with `HOG_LIMIT=1` and `source exp_hog_limit.mn`.
Finally `python3 analyze.py`. Delete `results.csv` first to start fresh.

## Results (server link capped at 10 Mbit/s, 5 MB file)

| Scenario | Metric | Baseline (no SDN) | SDN |
|---|---|---|---|
| single client, 10 runs | throughput (Mbit/s) | 9.16 ± 1.19 | 9.64 ± 0.03 |
| 3 clients at once, 3 runs each | per-client throughput (Mbit/s) | 3.45 ± 1.04 | 3.68 ± 1.98 |
| 3 clients at once | Jain fairness index | 0.999 | 0.943 |
| brute-force login, 20 s | attempts that reached the server | 99 of 99 | 3 of 20 |
| h2 download during the attack | throughput (Mbit/s) | 9.58 ± 0.10 | 9.61 ± 0.06 |

Hog scenario (h1 opens 4 downloads, h2 opens 1; controller present in both columns):

| Metric (h2, the single-connection host) | Limiter off | Limiter on |
|---|---|---|
| throughput (Mbit/s) | 1.72 ± 0.40 (n=7) | 3.47 ± 1.84 (n=6) |
| time to download 5 MB (s) | 25.7 ± 7.1 | 14.2 ± 4.8 |

* The controller blocked the attacker **89 ms** after the third failed login was logged (50 ms in a
  second run), and restored access after about 32 s (30 s timeout plus switch expiry check).
* The SDN adds no measurable overhead to normal transfers. Throughput differences in the
  single-client and concurrent tests are within run-to-run noise; the SDN does not make
  transfers faster there. Its benefit is access control with fast automatic reaction.
* The brute-force attack uses little bandwidth, so it does not reduce h2's throughput in either
  mode; the block protects the server and its logs rather than the link.
* With the hog limiter, h2's throughput roughly doubles and its download time falls by about 45%.
  h2 still does not reach a fair 5 Mbit/s (see limitations).
* `n=7` for the limiter-off case includes one extra run from an interrupted earlier attempt;
  dropping it leaves the mean at 1.72.
* All downloads were verified with SHA-256.

## Known limitations

* The portal is one gateway: all browser users appear to the server and controller as one IP (10.0.0.254), so a block affects every browser user, and per-user network policy is not possible through it.
* Roles and course enrolment are fixed in `webapp.py`; there is no sign-up or file deletion.

* The controller and server communicate through a shared file, which works because Mininet hosts
  share the host filesystem; a real deployment would use a network channel.
* Blocking is per source IP and only for the file-sharing port.
* The hog limiter's meter sits at the switch, after the capped server link. The hog's packets
  still use the shared link before being dropped, so the victim gets about 3.5 of a fair 5 Mbit/s.
  Detection takes about 6 s and limits last 20 s. Sample sizes are small (3 runs per set).
* No TLS; demo accounts are hard-coded.
