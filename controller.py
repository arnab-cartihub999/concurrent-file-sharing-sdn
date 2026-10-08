"""OS-Ken controller: learning switch + dynamic blocking + bandwidth monitor.

Dynamic blocking : the file server appends application events to events.jsonl.
                    After 3 failed logins from one IP the controller installs a
                    high-priority DROP flow for that IP -> server:5000 with a hard
                    timeout, so access is restored automatically.
Static policy    : STATIC_H1_BLOCK=1 installs a permanent h1 -> server:5000 drop
                    (used as the "static ACL" baseline).
Monitoring       : port statistics every 2 s -> stats.csv (per-port Mbit/s).
Hog limiter     : HOG_LIMIT=1 -> a host taking >60% of a busy link while another host is
                    active gets an OpenFlow meter (default 40% of the link) for 20 s.
Logs             : controller_events.log
"""
import os
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet

from policy import BlockPolicy, HogPolicy

_ws_broadcast = None


def set_ws_broadcast(func):
    global _ws_broadcast
    _ws_broadcast = func


def _emit(event_type: str, data: dict):
    if _ws_broadcast:
        try:
            _ws_broadcast({"type": event_type, "data": data})
        except Exception:
            pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.path.join(BASE_DIR, "events.jsonl")
LOG_FILE = os.path.join(BASE_DIR, "controller_events.log")
STATS_FILE = os.path.join(BASE_DIR, "stats.csv")

SERVER_IP = "10.0.0.4"
SERVICE_PORT = 5000
BLOCK_PRIORITY = 200
STATIC_PRIORITY = 150
BLOCK_SECONDS = int(os.environ.get("BLOCK_SECONDS", "30"))
STATIC_H1_BLOCK = os.environ.get("STATIC_H1_BLOCK", "0") == "1"
STATS_INTERVAL = 2
HOG_LIMIT = os.environ.get("HOG_LIMIT", "0") == "1"
LINK_MBPS = float(os.environ.get("LINK_MBPS", "10"))
LIMIT_PRIORITY = 160
PORT_IP = {1: "10.0.0.1", 2: "10.0.0.2", 3: "10.0.0.3"}   # client switch ports


class FileShareController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.policy = BlockPolicy(threshold=3, window=60, block_seconds=BLOCK_SECONDS)
        self.prev_ports = {}
        self.hog = HogPolicy(link_mbps=LINK_MBPS)
        if not os.path.exists(STATS_FILE):
            with open(STATS_FILE, "w") as f:
                f.write("ts,port,rx_mbps,tx_mbps\n")
        self.log("CONTROLLER_START static_h1_block=%s block_seconds=%s hog_limit=%s"
                 % (STATIC_H1_BLOCK, BLOCK_SECONDS, HOG_LIMIT))
        hub.spawn(self._tail_events)
        hub.spawn(self._poll_stats)

    # ------------------------------------------------------------- logging
    def log(self, msg):
        line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
        print(line, flush=True)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

    # ------------------------------------------------------------ flow utils
    def add_flow(self, dp, priority, match, actions, hard_timeout=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, hard_timeout=hard_timeout, flags=flags))

    def block_match(self, parser, src_ip):
        return parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=SERVER_IP,
                               ip_proto=6, tcp_dst=SERVICE_PORT)

    def install_block(self, ip, seconds):
        for dp in self.datapaths.values():
            ofp, parser = dp.ofproto, dp.ofproto_parser
            self.add_flow(dp, BLOCK_PRIORITY, self.block_match(parser, ip), [],
                          hard_timeout=seconds, flags=ofp.OFPFF_SEND_FLOW_REM)

    # -------------------------------------------------------- switch events
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.add_flow(dp, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        if STATIC_H1_BLOCK:
            # installed proactively, so it works regardless of earlier traffic
            self.add_flow(dp, STATIC_PRIORITY, self.block_match(parser, "10.0.0.1"), [])
            self.log("STATIC_BLOCK 10.0.0.1 -> %s:%d installed" % (SERVER_IP, SERVICE_PORT))
            _emit("static_block", {"ip": "10.0.0.1", "priority": STATIC_PRIORITY})

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        else:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, ev):
        m = ev.msg
        if m.priority == LIMIT_PRIORITY:
            ip = m.match.get("ipv4_dst")
            self.log("HOG_UNLIMIT ip=%s (rate limit expired)" % ip)
            _emit("hog_unlimit", {"ip": ip})
            return
        if m.priority == BLOCK_PRIORITY:
            ip = m.match.get("ipv4_src")
            self.policy.blocked.pop(ip, None)
            self.log("UNBLOCK ip=%s (block expired, access restored)" % ip)
            _emit("unblock", {"ip": ip})

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_handler(self, ev):
        m = ev.msg
        self.log("OPENFLOW_ERROR type=%s code=%s" % (m.type, m.code))

    # ------------------------------------------------------ hog rate limiter
    def apply_limit(self, dp, port):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        ip = PORT_IP[port]
        meter_id = 100 + port
        rate = self.hog.limit_kbps
        # re-create the meter so the call also works if it already exists
        dp.send_msg(parser.OFPMeterMod(dp, ofp.OFPMC_DELETE, ofp.OFPMF_KBPS, meter_id))
        band = parser.OFPMeterBandDrop(rate=rate, burst_size=max(100, rate // 2))
        dp.send_msg(parser.OFPMeterMod(dp, ofp.OFPMC_ADD, ofp.OFPMF_KBPS, meter_id, [band]))
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=SERVER_IP, ipv4_dst=ip,
                                ip_proto=6, tcp_src=SERVICE_PORT)
        inst = [parser.OFPInstructionMeter(meter_id),
                parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             [parser.OFPActionOutput(port)])]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=LIMIT_PRIORITY, match=match,
                                      instructions=inst, hard_timeout=self.hog.limit_seconds,
                                      flags=ofp.OFPFF_SEND_FLOW_REM))
        self.log("HOG_LIMIT ip=%s limit=%dkbps duration=%ds" % (ip, rate, self.hog.limit_seconds))
        _emit("hog_limit", {"ip": ip, "limit_kbps": rate, "duration": self.hog.limit_seconds})

    # --------------------------------------------------------- learning sw
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        eth = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        if eth is None:
            return
        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            self.add_flow(dp, 1, parser.OFPMatch(in_port=in_port, eth_dst=eth.dst), actions)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    # ------------------------------------- socket-app -> SDN integration
    def _tail_events(self):
        existed = os.path.exists(EVENTS_FILE)
        while not os.path.exists(EVENTS_FILE):
            hub.sleep(0.5)
        f = open(EVENTS_FILE, "r")
        if existed:
            f.seek(0, os.SEEK_END)          # ignore history from earlier runs
        while True:
            line = f.readline()
            if not line:
                hub.sleep(0.1)
                continue
            ip = self.policy.handle(line)
            if ip:
                try:
                    ts = __import__("json").loads(line).get("ts", time.time())
                except ValueError:
                    ts = time.time()
                self.install_block(ip, BLOCK_SECONDS)
                self.log("BLOCK ip=%s reason=3_failed_logins timeout=%ds response_ms=%.1f"
                         % (ip, BLOCK_SECONDS, (time.time() - ts) * 1000))
                _emit("block", {"ip": ip, "reason": "3_failed_logins", "timeout": BLOCK_SECONDS})

    # ------------------------------------------------ bandwidth monitoring
    def _poll_stats(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
            hub.sleep(STATS_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply(self, ev):
        now = time.time()
        rows = []
        client_rates = {}
        for s in ev.msg.body:
            if s.port_no > 0xffff00:
                continue
            key = (ev.msg.datapath.id, s.port_no)
            prev = self.prev_ports.get(key)
            self.prev_ports[key] = (now, s.rx_bytes, s.tx_bytes)
            if prev:
                dt = now - prev[0]
                if dt > 0:
                    if s.port_no in PORT_IP:
                        client_rates[s.port_no] = (s.tx_bytes - prev[2]) * 8 / dt / 1e6
                    rows.append("%.2f,%d,%.3f,%.3f" % (
                        now, s.port_no,
                        (s.rx_bytes - prev[1]) * 8 / dt / 1e6,
                        (s.tx_bytes - prev[2]) * 8 / dt / 1e6))
        if rows:
            with open(STATS_FILE, "a") as f:
                f.write("\n".join(rows) + "\n")
        if HOG_LIMIT and len(client_rates) == len(PORT_IP):
            for port in self.hog.update(client_rates):
                self.apply_limit(ev.msg.datapath, port)
