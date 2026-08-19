// classes.js

// =====================================================================
// 1. Packet Class
// =====================================================================
class Packet {
    constructor(id, sourceIp, destinationIp, protocol, port, payload) {
        this.id = id;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.protocol = protocol; // "TCP", "UDP", or "ICMP"
        this.port = port;         // E.g. 80, 443, 22
        this.payload = payload;   // E.g. "GET /index.html", "DROP TABLE users;"
        this.status = "INCOMING"; // "INCOMING", "ALLOWED", "BLOCKED"
        this.matchedRule = null;
    }

    hasMaliciousPayload() {
        const data = this.payload.toLowerCase();
        return (
            data.includes("select ") ||
            data.includes("drop table") ||
            data.includes("<script>") ||
            data.includes("ping -f")
        );
    }
}

// =====================================================================
// 2. Firewall Rule Class
// =====================================================================
class FirewallRule {
    constructor(id, action, protocol, sourceIp, port) {
        this.id = id;
        this.action = action;       // "ALLOW" or "BLOCK"
        this.protocol = protocol;   // "ANY", "TCP", "UDP", "ICMP"
        this.sourceIp = sourceIp;   // E.g. "192.168.1.5", "ANY", or "192.168.1.*"
        this.port = port;           // E.g. 80, 22, or "ANY"
    }

    matches(packet) {
        // Check Protocol
        if (this.protocol !== "ANY" && this.protocol !== packet.protocol) {
            return false;
        }

        // Check Port
        if (this.port !== "ANY" && parseInt(this.port) !== packet.port) {
            return false;
        }

        // Check IP with Wildcard support
        if (this.sourceIp !== "ANY") {
            if (this.sourceIp.endsWith("*")) {
                const prefix = this.sourceIp.slice(0, -1);
                if (!packet.sourceIp.startsWith(prefix)) {
                    return false;
                }
            } else if (this.sourceIp !== packet.sourceIp) {
                return false;
            }
        }

        return true;
    }
}

// =====================================================================
// 3. Firewall Engine Class
// =====================================================================
class FirewallEngine {
    constructor() {
        this.rules = [
            // Let's add some default rules
            new FirewallRule(1, "BLOCK", "TCP", "ANY", 22), // Block SSH port 22
            new FirewallRule(2, "ALLOW", "ANY", "ANY", "ANY") // Allow everything else by default
        ];
        this.logs = [];
    }

    addRule(action, protocol, sourceIp, port) {
        const newId = this.rules.length > 0 ? Math.max(...this.rules.map(r => r.id)) + 1 : 1;
        const rule = new FirewallRule(newId, action, protocol, sourceIp, port);

        // Put new rules at the top of the chain (highest priority)
        this.rules.unshift(rule);
        return rule;
    }

    deleteRule(id) {
        this.rules = this.rules.filter(rule => rule.id !== id);
    }

    process(packet) {
        // First, check if packet has malicious payloads (IDS - Intrusion Detection System check)
        if (packet.hasMaliciousPayload()) {
            packet.status = "BLOCKED";
            packet.matchedRule = { action: "BLOCK", reason: "Malicious Signature Detected" };
            this.logs.unshift({ packet, rule: packet.matchedRule, timestamp: new Date() });
            return packet;
        }

        // Process through firewall rules sequentially
        for (let rule of this.rules) {
            if (rule.matches(packet)) {
                packet.status = rule.action + "ED"; // "ALLOWED" or "BLOCKED"
                packet.matchedRule = rule;
                this.logs.unshift({ packet, rule, timestamp: new Date() });
                return packet;
            }
        }

        // Default Fallback
        packet.status = "BLOCKED";
        packet.matchedRule = { action: "BLOCK", reason: "Default Deny" };
        this.logs.unshift({ packet, rule: packet.matchedRule, timestamp: new Date() });
        return packet;
    }
}

// =====================================================================
// 4. Traffic Generator Class
// =====================================================================
class TrafficGenerator {
    constructor() {
        this.packetId = 1;
        this.cleanPayloads = [
            "GET /index.html HTTP/1.1",
            "POST /login username=admin",
            "GET /images/logo.png",
            "Host: google.com Connection: keep-alive"
        ];
        this.maliciousPayloads = [
            "SELECT * FROM users WHERE id = 1; --",
            "DROP TABLE products;",
            "<script>alert('hacked')</script>",
            "ping -f 192.168.1.1"
        ];
        this.protocols = ["TCP", "UDP", "ICMP"];
        this.ports = [80, 443, 22, 53, 8080];
        this.ips = [
            "192.168.1.10",
            "10.0.0.45",
            "172.16.254.1",
            "198.51.100.3",
            "8.8.8.8"
        ];
    }

    generate() {
        const isAttack = Math.random() < 0.3; // 30% chance of generating an attack packet
        const id = this.packetId++;
        const sourceIp = this.ips[Math.floor(Math.random() * this.ips.length)];
        const destIp = "192.168.1.1"; // The firewall acts as the gateway to this IP
        const protocol = this.protocols[Math.floor(Math.random() * this.protocols.length)];
        const port = this.ports[Math.floor(Math.random() * this.ports.length)];

        let payload;
        if (isAttack) {
            payload = this.maliciousPayloads[Math.floor(Math.random() * this.maliciousPayloads.length)];
        } else {
            payload = this.cleanPayloads[Math.floor(Math.random() * this.cleanPayloads.length)];
        }

        return new Packet(id, sourceIp, destIp, protocol, port, payload);
    }
}
// =====================================================================
// 5. Tetris Game OOP Class (For the Break Room)
// =====================================================================
class TetrisGame {
  // In classes.js inside class TetrisGame:
  constructor(canvasElement, onScoreUpdate, onGameOver) {
    this.canvas = canvasElement; // <--- We now pass the element directly
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.onScoreUpdate = onScoreUpdate;
    this.onGameOver = onGameOver;
    
    this.gridWidth = 10;
    this.gridHeight = 20;
    this.blockSize = 15;
    
    this.colors = [
      null,
      '#ff0055', // Z (Red)
      '#39ff14', // S (Green)
      '#00f0ff', // I (Cyan)
      '#ffbd03', // T (Yellow)
      '#ff00ff', // O (Magenta)
      '#ffffff', // L (White)
      '#7b2cbf'  // J (Purple)
    ];
    
    this.reset();
  }

  reset() {
    this.score = 0;
    this.grid = Array.from({ length: this.gridHeight }, () => Array(this.gridWidth).fill(0));
    this.gameOver = false;
    this.currentPiece = null;
    this.currentX = 0;
    this.currentY = 0;
    if (this.onScoreUpdate) this.onScoreUpdate(0);
  }

  // Define piece shapes
  createPiece(type) {
    const shapes = {
      'T': [[0, 0, 0], [1, 1, 1], [0, 1, 0]],
      'O': [[2, 2], [2, 2]],
      'I': [[0, 3, 0, 0], [0, 3, 0, 0], [0, 3, 0, 0], [0, 3, 0, 0]],
      'S': [[0, 4, 4], [4, 4, 0], [0, 0, 0]],
      'Z': [[5, 5, 0], [0, 5, 5], [0, 0, 0]],
      'L': [[0, 6, 0], [0, 6, 0], [0, 6, 6]],
      'J': [[0, 7, 0], [0, 7, 0], [7, 7, 0]]
    };
    const keys = Object.keys(shapes);
    const randomKey = keys[Math.floor(Math.random() * keys.length)];
    return shapes[randomKey];
  }

  spawnPiece() {
    this.currentPiece = this.createPiece();
    this.currentX = Math.floor((this.gridWidth - this.currentPiece[0].length) / 2);
    this.currentY = 0;
    
    if (this.checkCollision(this.currentX, this.currentY, this.currentPiece)) {
      this.gameOver = true;
      if (this.onGameOver) this.onGameOver();
    }
  }

  checkCollision(xOffset, yOffset, piece) {
    for (let r = 0; r < piece.length; r++) {
      for (let c = 0; c < piece[r].length; c++) {
        if (piece[r][c] !== 0) {
          const nextX = xOffset + c;
          const nextY = yOffset + r;
          
          if (nextX < 0 || nextX >= this.gridWidth || nextY >= this.gridHeight) {
            return true;
          }
          if (nextY >= 0 && this.grid[nextY][nextX] !== 0) {
            return true;
          }
        }
      }
    }
    return false;
  }

  merge() {
    for (let r = 0; r < this.currentPiece.length; r++) {
      for (let c = 0; c < this.currentPiece[r].length; c++) {
        if (this.currentPiece[r][c] !== 0) {
          this.grid[this.currentY + r][this.currentX + c] = this.currentPiece[r][c];
        }
      }
    }
  }

  clearLines() {
    let linesCleared = 0;
    for (let r = this.gridHeight - 1; r >= 0; r--) {
      if (this.grid[r].every(value => value !== 0)) {
        this.grid.splice(r, 1);
        this.grid.unshift(Array(this.gridWidth).fill(0));
        linesCleared++;
        r++; // Check same row index again since we spliced
      }
    }
    if (linesCleared > 0) {
      this.score += linesCleared * 100;
      if (this.onScoreUpdate) this.onScoreUpdate(this.score);
    }
  }

  rotate() {
    const rotated = this.currentPiece[0].map((_, index) =>
      this.currentPiece.map(row => row[index]).reverse()
    );
    if (!this.checkCollision(this.currentX, this.currentY, rotated)) {
      this.currentPiece = rotated;
    }
  }

  move(dir) {
    if (!this.checkCollision(this.currentX + dir, this.currentY, this.currentPiece)) {
      this.currentX += dir;
    }
  }

  drop() {
    if (this.gameOver) return;
    
    if (!this.currentPiece) {
      this.spawnPiece();
      return;
    }
    
    if (!this.checkCollision(this.currentX, this.currentY + 1, this.currentPiece)) {
      this.currentY++;
    } else {
      this.merge();
      this.clearLines();
      this.spawnPiece();
    }
  }

  draw() {
    if (!this.canvas) return;
    this.ctx.fillStyle = '#070b19';
    this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
    
    // Draw Grid Board
    for (let r = 0; r < this.gridHeight; r++) {
      for (let c = 0; c < this.gridWidth; c++) {
        if (this.grid[r][c] !== 0) {
          this.ctx.fillStyle = this.colors[this.grid[r][c]];
          this.ctx.fillRect(c * this.blockSize, r * this.blockSize, this.blockSize - 1, this.blockSize - 1);
        }
      }
    }
    
    // Draw Falling Piece
    if (this.currentPiece) {
      for (let r = 0; r < this.currentPiece.length; r++) {
        for (let c = 0; c < this.currentPiece[r].length; c++) {
          if (this.currentPiece[r][c] !== 0) {
            this.ctx.fillStyle = this.colors[this.currentPiece[r][c]];
            this.ctx.fillRect((this.currentX + c) * this.blockSize, (this.currentY + r) * this.blockSize, this.blockSize - 1, this.blockSize - 1);
          }
        }
      }
    }
  }
}