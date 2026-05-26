from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel


def topologiSkripsi():
    net = Mininet(controller=RemoteController,
                  switch=OVSKernelSwitch)

    print("*** Menambahkan Controller Ryu (Remote)")
    c0 = net.addController('c0',
                           controller=RemoteController,
                           ip='127.0.0.1',
                           port=6653)

    print("*** Menambahkan Switch SDN (OpenFlow 1.3)")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # ── KLIEN ────────────────────────────────────────────────────────────────
    # Representasi mahasiswa UNSRAT yang mengakses Portal Akademik
    print("*** Menambahkan Host Klien (simulasi mahasiswa)")
    h1 = net.addHost('h1', ip='10.0.0.11/24', mac='00:00:00:00:01:11')
    h2 = net.addHost('h2', ip='10.0.0.12/24', mac='00:00:00:00:01:12')
    h3 = net.addHost('h3', ip='10.0.0.13/24', mac='00:00:00:00:01:13')
    h4 = net.addHost('h4', ip='10.0.0.14/24', mac='00:00:00:00:01:14')

    # ── SERVER POOL ───────────────────────────────────────────────────────────
    print("*** Menambahkan Server Pool")
    # Replika Portal Akademik Inspire (target load balancing)
    portal1 = net.addHost('portal1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    portal2 = net.addHost('portal2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')

    # Server E-Learning (sumber trafik interferensi di Skenario 3)
    elearn  = net.addHost('elearn',  ip='10.0.0.3/24', mac='00:00:00:00:00:03')

    # ── LINK ─────────────────────────────────────────────────────────────────
    print("*** Menghubungkan host ke switch")
    net.addLink(h1,      s1, port1=0, port2=1)
    net.addLink(h2,      s1, port1=0, port2=2)
    net.addLink(h3,      s1, port1=0, port2=3)
    net.addLink(h4,      s1, port1=0, port2=4)
    net.addLink(portal1, s1, port1=0, port2=5)
    net.addLink(portal2, s1, port1=0, port2=6)
    net.addLink(elearn,  s1, port1=0, port2=7)

    print("*** Memulai Jaringan")
    net.build()
    c0.start()
    s1.start([c0])


    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topologiSkripsi()