# NetShield Engine 🛡️🎮

An interactive, browser-based network firewall simulator built using HTML5, CSS3, JavaScript (OOP), and React. It includes a built-in "Break Room" Tetris game easter egg to showcase creative design and gamified simulation.

## 🚀 The Problem it Solves
Understanding networking and cybersecurity—such as IP routing, packet inspection, port blocking, and security rules—can be abstract and difficult to visualize. `NetShield Engine` turns these networking concepts into a live simulation where developers and students can watch network traffic fly across the screen and customize firewall rules to intercept threats.

## 🛠️ Features
- **Object-Oriented Simulation Core:** Designed using modular JavaScript classes (`Packet`, `FirewallRule`, `FirewallEngine`, `TrafficGenerator`, `TetrisGame`) to keep business logic separate from the visual React layer.
- **Rule Controller:** Add or remove custom rules for Protocols (TCP/UDP/ICMP), Ports, and IP subnet wildcards (like `192.168.1.*`) on-the-fly.
- **Intrusion Detection System (IDS):** The packet class performs self-inspection of its payload and automatically flags/blocks malicious SQL injection or Cross-Site Scripting (XSS) strings.
- **Visual Traffic Arena:** Smooth CSS animations show packets moving across the screen, passing through a security gateway, and updating color status (Allowed = Green, Blocked = Red).
- **Interactive Logs & Real-Time Stats:** Track how many threats have been blocked and read detailed logs of which rules triggered each decision.
- **🎮 The Break Room (Tetris Easter Egg):** A fully functional, playable Tetris game built from scratch using vanilla OOP JS and HTML5 Canvas, responding to arrow keys directly in the sidebar.

## ⚙️ Setup & Installation

### Option 1: Using a local Python server (Recommended)
Since this project uses client-side Babel compilation, running it on a local server prevents browser security/CORS issues:

1. Clone the repository to your desktop or laptop:
   ```bash
   git clone https://github.com/YOUR_USERNAME/net-shield-engine.git
   cd net-shield-engine

   How to Use the Firewall
🛡️ Managing Security Policies
By default, TCP Port 22 (SSH) traffic is blocked. All other traffic is allowed.
To add a rule, use the Add Policy form in the left panel. For example:
Set Action: BLOCK
Protocol: TCP
IP Source: ANY
Port: 80
Click Apply Rule. All incoming traffic to port 80 will now be blocked.
🎮 Playing Tetris in the Break Room
Click the Play Tetris (Bored?) button in the right panel.
Click on the game area and use your keyboard arrow keys to play:
◀ / ▶ Left/Right Arrow keys to move pieces.
▲ Up Arrow to rotate the block.
▼ Down Arrow to drop the block faster.