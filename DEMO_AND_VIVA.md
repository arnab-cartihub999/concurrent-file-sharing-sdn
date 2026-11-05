# Demo script and viva guide

## Before the demo (2 minutes)
Open two terminals in `~/file-sharing-sdn`.

Terminal A:
```
sudo service openvswitch-switch start
HOG_LIMIT=1 osken-manager controller.py
```
Terminal B:
```
sudo mn -c
sudo python3 topology.py --web
```
At `mininet>`:
```
pingall
server python3 server.py > server.log 2>&1 &
```
Terminal C (web app, normal user, after the server is started below):
```
cd ~/file-sharing-sdn
python3 webapp.py
```
Then open http://localhost:8080 in the browser.

Fallbacks: `sudo mn -c` if Mininet complains about leftovers; restart the controller if `pingall` loses packets.

## CampusShare demo (about 4 minutes, do this first)

1. Open http://localhost:8080. Say: "CampusShare is a college assignment portal. The file-sharing system we built is its storage and transfer engine."
2. Log in as **alice** (student): assignments with due dates and status; submit a file to *Socket programming lab report*; it shows *Submitted*; download it again.
3. Log out, log in as **bob**; submit to the same assignment. Point out that bob only ever sees his own file.
4. Log in as **prof** (faculty): *Review submissions* shows alice and bob; download a submission, enter marks and feedback, Save. Publish a new assignment, then upload a course material under *Course materials*.
5. Back as **alice**: marks and feedback appear; the new material is downloadable.
6. Point at the right panel: live per-port traffic from the controller while files move.
7. SDN policy: log out and enter a wrong password **three times**. The page says the server is unreachable (blocked); a red `BLOCK` event appears; about 30 s later log in again (green `UNBLOCK`).
8. In Mininet right after the third failure: `sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=200`.

## Command-line demo (about 5 minutes)

1. **Architecture (30 s)** – show the diagram in README: h1-h3, s1, server, controller, events.jsonl link.
2. **Connectivity** – `pingall` shows 0% loss through the OS-Ken learning switch.
3. **Authentication + upload/download**
   ```
   h2 sh -c 'printf "LIST\nQUIT\n" | python3 client.py --host 10.0.0.4 --user alice --password alice123'
   h2 sh -c 'printf "UPLOAD demo.bin\nQUIT\n" | python3 client.py --host 10.0.0.4 --user alice --password alice123'
   h1 sh -c 'printf "DOWNLOAD demo.bin\nQUIT\n" | python3 client.py --host 10.0.0.4 --user bob --password bob123'
   ```
   (create `demo.bin` first with `sh head -c 5000000 /dev/urandom > demo.bin`; compare `sha256sum` of both files.)
4. **Safety** – `h2 sh -c 'printf "DOWNLOAD ../server.py\nQUIT\n" | python3 client.py --host 10.0.0.4 --user admin --password 1234'` → rejected.
5. **Dynamic SDN policy**
   ```
   h3 sh -c 'for i in 1 2 3; do python3 client.py --host 10.0.0.4 --user admin --password wrong; done'
   h3 sh -c 'printf "LIST\nQUIT\n" | timeout 5 python3 client.py --host 10.0.0.4 --user admin --password 1234'
   h2 sh -c 'printf "LIST\nQUIT\n" | python3 client.py --host 10.0.0.4 --user admin --password 1234'
   sh ovs-ofctl -O OpenFlow13 dump-flows s1
   sh cat controller_events.log
   ```
   Point out: priority-200 drop flow, BLOCK response ~89 ms, h2 unaffected, UNBLOCK after ~30 s.
6. **Monitoring** – `sh tail -5 stats.csv`.
7. **Results** – `sh cat results_summary.md`; explain baseline vs SDN and the hog limiter table.

## Viva questions and short answers

- **Why TCP?** Files need reliable, ordered delivery; TCP gives that, we only add message framing.
- **How do you handle TCP being a byte stream?** Line-based commands plus exact byte counts (`UPLOAD name size`, `OK size`), so no end markers that file data could contain.
- **Why threads?** One daemon thread per client keeps the code simple; blocking I/O releases the GIL, and transfers are I/O-bound. Async would scale further; threads suffice for the demo load.
- **How do you avoid races?** Metadata writes are under a lock and atomic (temp file + rename); uploads go to `.part` and are renamed on success.
- **Path traversal?** Names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`; tested in selftest.
- **Passwords?** Salted PBKDF2 hashes in memory; no TLS (limitation).
- **How does the socket app talk to the SDN?** Server appends JSON events to `events.jsonl`; the controller tails it. Works because Mininet hosts share the filesystem; a real system would use a network channel (REST/message queue).
- **What exactly does the controller do?** After 3 AUTH_FAIL from one IP in 60 s it installs a priority-200 drop flow IP→server:5000 with a 30 s hard timeout; flow-removed message logs UNBLOCK.
- **Why those priorities?** Learned forwarding 1, table-miss 0, static ACL 150, hog limiter 160, block 200 – the more specific policy always wins.
- **What is the hog limiter?** If one host takes >70% of a busy server link while others are active (two consecutive polls), an OpenFlow meter limits its server→host traffic to 50% of the link for 20 s. Victim throughput roughly doubled (1.72 → 3.47 Mbit/s).
- **Why was the limiter first unstable?** Thresholds were too tight and limited the victim; raised share to 0.7 and cap to 0.5 and unit-tested the policy.
- **What is the baseline?** Same topology with a standalone switch and no controller.
- **What do results show/not show?** SDN adds no measurable overhead; blocking protects the server from brute force; the limiter helps victims. They do not show SDN speeds up transfers. Samples are small (n=3–10).
- **Jain index?** (Σx)²/(n·Σx²); 1 = perfectly fair.
- **Limitations?** Shared-file channel, per-IP policy, no TLS, hard-coded accounts, meter applied after the bottleneck, small samples.

### Application questions
- **What real-life application is this?** A campus assignment and course-material portal (CampusShare): students submit work, faculty publish materials and grade, admin oversees. File sharing is the core service underneath.
- **Where do the sockets come in?** The portal never touches stored files directly: every upload and download is a TCP connection to the file server made with `fsclient.py`. The browser only speaks HTTP to the portal.
- **How does the SDN take part?** The portal's connections cross the switch (`topology.py --web` attaches it as 10.0.0.254, port 5), so the controller monitors them (live panel) and blocks the gateway after 3 failed logins.
- **Who may see what?** Students: own submissions and course materials. Faculty/admin: all submissions. Enforced in the portal on every download. Limitation: the raw file server has no ACL, so the command-line client can still list everything.
- **Why is the whole portal blocked after 3 bad logins?** All browser users share one gateway IP. Per-user blocking would need the server to report user names and the controller to map users to flows; listed as future work.
- **How are late submissions handled?** The portal compares the submission time with the due date and flags it Late; resubmission replaces the record and clears an old grade.
