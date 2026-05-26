import threading
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, arp


class LeastConnectionSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LeastConnectionSDN, self).__init__(*args, **kwargs)

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
                'port': 5, 'connections': 0, 'total_requests': 0, 'healthy': True
            },
            {
                'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02',
                'port': 6, 'connections': 0, 'total_requests': 0, 'healthy': True
            },
        ]

        self.logger.info("✅ LeastConnectionSDN siap. Server pool: %s",
                         [s['ip'] for s in self.portal_servers])

    # ─────────────────────────────────────────────────────────────────────────
    # A. SWITCH HANDSHAKE: pasang table-miss flow entry
    # ─────────────────────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("✅ Switch %016x terhubung.", datapath.id)

    # ─────────────────────────────────────────────────────────────────────────
    # B. LEAST-CONNECTION: pilih server dengan koneksi aktif paling sedikit
    # ─────────────────────────────────────────────────────────────────────────

    def get_least_connection_server(self):
        """
        Harus dipanggil DALAM konteks self._lock.
        Tiebreaker: jika connections sama, pilih server dengan total_requests
        lebih sedikit (distribusi lebih merata jangka panjang).
        Server unhealthy dilewati.
        """
        candidates = [s for s in self.portal_servers if s['healthy']]
        if not candidates:
            return None
        return min(candidates,
                   key=lambda s: (s['connections'], s['total_requests']))

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

        # Catat mapping MAC → port untuk L2 forwarding biasa
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # ── C1. ARP untuk VIP Portal ─────────────────────────────────────
        if arp_pkt and arp_pkt.dst_ip == self.VIP_PORTAL:
            self._handle_arp(datapath, in_port, eth, arp_pkt)
            return

        # ── C2. TCP menuju VIP → Load Balancing ──────────────────────────
        if ip_pkt and tcp_pkt and ip_pkt.dst == self.VIP_PORTAL:
            is_syn = bool(tcp_pkt.bits & 0x02)
            if not is_syn:
                # Bukan SYN (ACK, data, FIN, RST): sudah ditangani flow table.
                # Paket ini tidak seharusnya sampai di sini kecuali flow belum
                # terpasang. Abaikan saja.
                return

            # Lock saat baca + tulis counter (thread safety)
            with self._lock:
                target_server = self.get_least_connection_server()
                if target_server is None:
                    self.logger.error("❌ Semua server tidak sehat! Paket dibuang.")
                    return

                # Naikkan counter SEBELUM install flow agar tidak ada
                # jeda waktu di mana counter belum terupdate.
                target_server['connections']    += 1
                target_server['total_requests'] += 1

            target_ip   = target_server['ip']
            target_mac  = target_server['mac']
            target_port = target_server['port']

            self.logger.info(
                "🚀 Least-Conn: %s:%d → VIP → %s  [aktif=%d | total=%d]",
                ip_pkt.src, tcp_pkt.src_port,
                target_ip,
                target_server['connections'],
                target_server['total_requests'],
            )

            # ── Rule MAJU: client→VIP  =====>  client→server ─────────────
            # TIDAK diberi OFPFF_SEND_FLOW_REM — identifikasi server
            # dilakukan dari reverse flow agar tidak double-decrement.
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
                idle_timeout=5,    # sesuai durasi koneksi HTTP
                hard_timeout=60,   # safety net absolut
                flags=0,           # tidak perlu FLOW_REMOVED di sini
            )

            # ── Rule BALIK: server→client  =====>  VIP→client ────────────
            # HANYA reverse flow yang mendapat OFPFF_SEND_FLOW_REM.
            # Saat expired, flow_removed_handler membaca ipv4_src = server_IP
            # untuk identifikasi server dan mengurangi counter.
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
                idle_timeout=8,    # sedikit lebih panjang dari forward
                hard_timeout=65,   # sedikit lebih panjang dari forward
                flags=datapath.ofproto.OFPFF_SEND_FLOW_REM,  # ← HANYA di sini
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
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)

    # ─────────────────────────────────────────────────────────────────────────
    # D. FLOW REMOVED: kurangi counter saat koneksi selesai
    # ─────────────────────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        Event ini HANYA datang dari REVERSE flow (karena hanya reverse flow
        yang mendapat OFPFF_SEND_FLOW_REM).

        Reverse flow match: ipv4_src = server_IP, ipv4_dst = client_IP.
        Kita identifikasi server dari ipv4_src, lalu kurangi counter-nya.

        Perbedaan dari versi lama:
          LAMA: cek ipv4_dst == server_IP  ← SALAH (selalu False, forward
                flow punya ipv4_dst = VIP bukan server IP)
          BARU: cek ipv4_src == server_IP  ← BENAR (reverse flow punya
                ipv4_src = server_IP)
        """
        match = ev.msg.match

        # Identifikasi server dari ipv4_src reverse flow
        server_ip = None
        if 'ipv4_src' in match:
            candidate  = match['ipv4_src']
            server_ips = {s['ip'] for s in self.portal_servers}
            if candidate in server_ips:
                server_ip = candidate

        if server_ip is None:
            return  # bukan reverse flow kita, abaikan

        with self._lock:
            for server in self.portal_servers:
                if server['ip'] == server_ip:
                    server['connections'] = max(0, server['connections'] - 1)
                    self.logger.info(
                        "✅ Koneksi selesai → %s | Aktif sekarang: %d",
                        server_ip, server['connections'],
                    )
                    return

    # ─────────────────────────────────────────────────────────────────────────
    # E. HEALTH CHECK (skeleton)
    # ─────────────────────────────────────────────────────────────────────────

    def mark_server_unhealthy(self, server_ip: str):
        with self._lock:
            for server in self.portal_servers:
                if server['ip'] == server_ip:
                    server['healthy'] = False
                    self.logger.warning("⚠️  Server %s ditandai TIDAK SEHAT.", server_ip)
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
                    'connections':    s['connections'],
                    'total_requests': s['total_requests'],
                }
                for s in self.portal_servers
            ]

    # ─────────────────────────────────────────────────────────────────────────
    # F. HELPER: install flow entry ke switch
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
    # G. HELPER: balas ARP request untuk VIP
    # ─────────────────────────────────────────────────────────────────────────

    def _handle_arp(self, datapath, in_port, eth_pkt, arp_pkt):
        """
        Jawab ARP request 'Who has VIP_PORTAL?' dengan MAC virtual.
        Client tidak perlu tahu IP server asli (NAT transparan).
        """
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