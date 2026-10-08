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
                              |
                              | OpenFlow 1.3
                        +-----+-----+
                        |    s1     |   Open vSwitch
                        +-+--+--+-+-+
        port 1 |  port 2 | port 3|  | port 4 	(capped, default 10 Mbit/s)
              h1        h2      h3  
              						
          10.0.0.1  10.0.0.2  10.0.0.3 server 10.0.0.4 : TCP 5000
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

| File                                         | Purpose                                                                               |
| -------------------------------------------- | ------------------------------------------------------------------------------------- |
| `server.py`                                | Threaded TCP file server: authentication, LIST, UPLOAD, DOWNLOAD, metadata, event log |
| `fsclient.py`                              | Client library implementing the protocol                                              |
| `client.py`                                | Interactive command-line client                                                       |
| `controller.py`                            | OS-Ken controller: learning switch, dynamic blocking, bandwidth monitor, hog limiter  |
| `policy.py`                                | Pure-Python policies:`BlockPolicy` (3 failures / 60 s) and `HogPolicy`            |
| `topology.py`                              | Mininet topology;`--mode sdn` or `--mode baseline`, link cap options              |
| `bench.py`, `analyze.py`                 | Benchmark client and results summariser                                               |
| `exp_sdn.mn`, `exp_baseline.mn`          | Access-control / throughput experiments (run from the Mininet CLI)                    |
| `exp_hog_nolimit.mn`, `exp_hog_limit.mn` | Hog-limiter experiment, limiter off / on                                              |
| `selftest.py`                              | Local loopback tests of the server (no Mininet needed)                                |
| `results.csv`, `results_summary.md`      | Raw and summarised experiment results                                                 |

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
`admin/1234`, `alice/alice123`, `bob/bob123`. Traffic is not encrypted (no TLS).

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

| Scenario                       | Metric                           | Baseline (no SDN) | SDN          |
| ------------------------------ | -------------------------------- | ----------------- | ------------ |
| single client, 10 runs         | throughput (Mbit/s)              | 9.16 ± 1.19      | 9.64 ± 0.03 |
| 3 clients at once, 3 runs each | per-client throughput (Mbit/s)   | 3.45 ± 1.04      | 3.68 ± 1.98 |
| 3 clients at once              | Jain fairness index              | 0.999             | 0.943        |
| brute-force login, 20 s        | attempts that reached the server | 99 of 99          | 3 of 20      |
| h2 download during the attack  | throughput (Mbit/s)              | 9.58 ± 0.10      | 9.61 ± 0.06 |

Hog scenario (h1 opens 4 downloads, h2 opens 1; controller present in both columns):

| Metric (h2, the single-connection host) | Limiter off        | Limiter on         |
| --------------------------------------- | ------------------ | ------------------ |
| throughput (Mbit/s)                     | 1.72 ± 0.40 (n=7) | 3.47 ± 1.84 (n=6) |
| time to download 5 MB (s)               | 25.7 ± 7.1        | 14.2 ± 4.8        |

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

* The controller and server communicate through a shared file, which works because Mininet hosts
  share the host filesystem; a real deployment would use a network channel.
* Blocking is per source IP and only for the file-sharing port.
* The hog limiter's meter sits at the switch, after the capped server link. The hog's packets
  still use the shared link before being dropped, so the victim gets about 3.5 of a fair 5 Mbit/s.
  Detection takes about 6 s and limits last 20 s. Sample sizes are small (3 runs per set).
* No TLS; demo accounts are hard-coded.
