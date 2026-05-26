# SDN-Based Network Load Balancer Simulation

This repository contains a comprehensive **Software-Defined Networking (SDN)** simulation conducted in a laboratory environment. The project models the network topology of the IT Center at Universitas Sam Ratulangi (UPT TIK UNSRAT) to evaluate and mitigate resource contention during peak academic events.

This simulation implements and benchmarks two load-balancing algorithms—**Least-Connection (Dynamic)** and **Round-Robin (Static)**—running on an SDN architecture to protect critical academic web portals from heavy traffic bursts.

## 🚀 Key Features

* **Software-Defined Networking (SDN):** Decouples the control plane from the data plane using the OpenFlow 1.3 protocol.
* **Dynamic Load Balancing:** Custom Python-based Ryu Controller application that actively monitors TCP connection counts to intelligently distribute server workloads.
* **Laboratory Simulation Environment:** Safe, isolated, and scalable network emulation using Mininet to safely test high-stress traffic scenarios without disrupting production servers.
* **Stress Testing & Traffic Injection:** Utilizes Apache Bench (`ab`) for concurrent HTTP requests and D-ITG for background interference traffic generation.

## 🛠️ Technology Stack

* **Control Plane:** Ryu SDN Controller Framework
* **Data Plane & Virtualization:** Mininet Emulator, Open vSwitch (OVS)
* **Protocol:** OpenFlow 1.3
* **Language:** Python 3
* **Testing Tools:** Apache Bench (`ab`), Distributed Internet Traffic Generator (D-ITG)

## 🏗️ Architecture & Topology

The topology is designed using a star (hub-and-spoke) model, segregating the network into a distinct control plane and data plane. 

* **Controller:** Centralized Ryu Controller orchestrating flow rules.
* **Switch:** OpenFlow-enabled virtual switch routing the packets.
* **Clients (Hosts 1-4):** Simulated university users accessing the portals.
* **Server Pool:** Replicated Nginx backend servers representing the Academic Portal (`portal1`, `portal2`) under a Virtual IP (`10.0.0.100`), alongside an interference target (`elearn`).

## ⚙️ Installation & Usage

### Prerequisites
Ensure your laboratory environment or virtual machine has the following installed:
* Python 3.x
* Mininet
* Ryu Controller
* Apache Bench (`apache2-utils`)
