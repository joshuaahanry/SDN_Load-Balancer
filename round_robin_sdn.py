import threading
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, arp


class RoundRobinSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RoundRobinSDN, self).__init__(*args, **kwargs)

        # ── Thread safety ─────────────────────────────────────────────────────
        self._lock = threading.Lock()

        # ── L2 Forwarding Table ───────────────────────────────────────────────
        self.mac_to_port = {}

        # ── Virtual IP (VIP) Portal Akademik ─────────────────────────────────
        self.VIP_PORTAL = '10.0.0.100'
        self.VIP_MAC    = '00:00:00:00:00:99'

        # ── Server Farm ───────────────────────────────────────────────────────
        # Port switch disesuaikan dengan topologi_sdn_unsrat.py:
        #   portal1 = port 5, portal2 = port 6
        self.portal_servers = [
            {
                'ip': '10.0.0.1', 'mac': '00:00:00:00:00:01',
                'port': 5, 'healthy': True, 'total_requests': 0
            },
            {
                'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02',
                'port': 6, 'healthy': True, 'total_requests': 0
            },
        ]

        # ── Round Robin Index ─────────────────────────────────────────────────
        self._rr_index = 0

        self.logger.info("✅ RoundRobinSDN siap. Server pool: %s",
                         [s['ip'] for s in self.portal_servers])

    # ─────────────────────────────────────────────────────────────────────────
    # A. SWITCH HANDSHAKE
    # ─────────────────────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions,
                      idle_timeout=0)
        self.logger.info("✅ Switch %016x terhubung. Round-Robin aktif.",
                         datapath.id)

    # ─────────────────────────────────────────────────────────────────────────
    # B. ROUND ROBIN: ambil server berikutnya secara bergiliran
    # ─────────────────────────────────────────────────────────────────────────

    def get_next_server(self):
        """
        Harus dipanggil DALAM konteks self._lock.
        Melewati server yang tidak healthy.
        Jika semua server tidak sehat, kembalikan None.
        """
        n = len(self.portal_servers)
        for _ in range(n):
            server = self.portal_servers[self._rr_index]
            self._rr_index = (self._rr_index + 1) % n
            if server['healthy']:
                server['total_requests'] += 1
                return server
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # C. PACKET-IN HANDLER
    # ─────────────────────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        pkt     = packet.Packet(msg.data)
        eth     = pkt.get_protocol(ethernet.ethernet)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth is None:
            return

        # Catat mapping MAC → port
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # ── C1. ARP untuk VIP Portal ─────────────────────────────────────
        if arp_pkt and arp_pkt.dst_ip == self.VIP_PORTAL:
            self._handle_arp(datapath, in_port, eth, arp_pkt)
            return

        # ── C2. TCP menuju VIP → Round Robin ─────────────────────────────
        if ip_pkt and tcp_pkt and ip_pkt.dst == self.VIP_PORTAL:
            is_syn = bool(tcp_pkt.bits & 0x02)
            if not is_syn:
                return  # biarkan flow table switch yang menangani

            with self._lock:
                target_server = self.get_next_server()

            if target_server is None:
                self.logger.error("❌ Semua server tidak sehat! Paket dibuang.")
                return

            target_ip   = target_server['ip']
            target_mac  = target_server['mac']
            target_port = target_server['port']

            self.logger.info(
                "🔄 Round-Robin: %s:%d → VIP → %s  [total=%d]",
                ip_pkt.src, tcp_pkt.src_port,
                target_ip, target_server['total_requests'],
            )

            # ── Rule MAJU: client→VIP  =====>  client→server ─────────────
            fwd_match = parser.OFPMatch(
                eth_type=0x0800, ip_proto=6,
                ipv4_src=ip_pkt.src,      ipv4_dst=self.VIP_PORTAL,
                tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port,
            )
            fwd_actions = [
                parser.OFPActionSetField(ipv4_dst=target_ip),
                parser.OFPActionSetField(eth_dst=target_mac),
                parser.OFPActionOutput(target_port),
            ]
            self.add_flow(
                datapath, priority=10,
                match=fwd_match, actions=fwd_actions,
                idle_timeout=5,
                hard_timeout=60,
            )

            # ── Rule BALIK: server→client  =====>  VIP→client ────────────
            rev_match = parser.OFPMatch(
                eth_type=0x0800, ip_proto=6,
                ipv4_src=target_ip,        ipv4_dst=ip_pkt.src,
                tcp_src=tcp_pkt.dst_port,  tcp_dst=tcp_pkt.src_port,
            )
            rev_actions = [
                parser.OFPActionSetField(ipv4_src=self.VIP_PORTAL),
                parser.OFPActionSetField(eth_src=self.VIP_MAC),
                parser.OFPActionOutput(in_port),
            ]
            self.add_flow(
                datapath, priority=10,
                match=rev_match, actions=rev_actions,
                idle_timeout=8,
                hard_timeout=65,
            )

            # ── Kirim paket SYN ke server terpilih ───────────────────────
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=fwd_actions,
                data=msg.data,
            )
            datapath.send_msg(out)
            return

        # ── C3. Bukan tujuan VIP → L2 Forwarding biasa ───────────────────
        out_port = ofproto.OFPP_FLOOD
        if eth.dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][eth.dst]

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=eth.dst, eth_src=eth.src
            )
            self.add_flow(datapath, priority=1, match=match, actions=actions,
                          idle_timeout=60)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)

    # ─────────────────────────────────────────────────────────────────────────
    # D. HEALTH CHECK (skeleton)
    # ─────────────────────────────────────────────────────────────────────────

    def mark_server_unhealthy(self, server_ip: str):
        with self._lock:
            for server in self.portal_servers:
                if server['ip'] == server_ip:
                    server['healthy'] = False
                    self.logger.warning("⚠️  Server %s ditandai TIDAK SEHAT.",
                                        server_ip)
                    return

    def mark_server_healthy(self, server_ip: str):
        with self._lock:
            for server in self.portal_servers:
                if server['ip'] == server_ip:
                    server['healthy'] = True
                    self.logger.info("✅ Server %s pulih kembali.", server_ip)
                    return

    def get_stats(self) -> list:
        with self._lock:
            return [
                {
                    'ip':             s['ip'],
                    'healthy':        s['healthy'],
                    'total_requests': s['total_requests'],
                }
                for s in self.portal_servers
            ]

    # ─────────────────────────────────────────────────────────────────────────
    # E. HELPER: install flow entry ke switch
    # ─────────────────────────────────────────────────────────────────────────

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0, flags=0):
        parser = datapath.ofproto_parser
        inst   = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions
        )]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            flags=flags,
        )
        datapath.send_msg(mod)

    # ─────────────────────────────────────────────────────────────────────────
    # F. HELPER: balas ARP request untuk VIP
    # ─────────────────────────────────────────────────────────────────────────

    def _handle_arp(self, datapath, in_port, eth_pkt, arp_pkt):
        parser = datapath.ofproto_parser

        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(ethernet.ethernet(
            ethertype=eth_pkt.ethertype,
            dst=eth_pkt.src,
            src=self.VIP_MAC,
        ))
        reply_pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.VIP_MAC,
            src_ip=self.VIP_PORTAL,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip,
        ))
        reply_pkt.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_ANY,
            actions=actions,
            data=reply_pkt.data,
        )
        datapath.send_msg(out)
        self.logger.debug("ARP reply VIP dikirim ke port %d", in_port)