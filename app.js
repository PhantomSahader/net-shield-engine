// app.js

// Initialize our OOP classes once (outside of the React components so they persist)
const engine = new FirewallEngine();
const generator = new TrafficGenerator();

function App() {
  // =====================================================================
  // 1. React State Hooks
  // =====================================================================
  const [packets, setPackets] = React.useState([]); // Active packets on screen
  const [rules, setRules] = React.useState([...engine.rules]); // Active firewall rules
  const [logs, setLogs] = React.useState([]); // History log
  const [isSimulating, setIsSimulating] = React.useState(true); // Play/Pause state
  
  // Counters for statistics
  const [stats, setStats] = React.useState({ allowed: 0, blocked: 0, threats: 0 });

  // Form State for creating a new rule
  const [formAction, setFormAction] = React.useState("BLOCK");
  const [formProtocol, setFormProtocol] = React.useState("TCP");
  const [formIp, setFormIp] = React.useState("ANY");
  const [formPort, setFormPort] = React.useState("ANY");

  // =====================================================================
  // 2. The Simulation Loop (useEffect)
  // =====================================================================
  React.useEffect(() => {
    if (!isSimulating) return;

    // Set up a loop to spawn a new packet every 1.5 seconds
    const interval = setInterval(() => {
      // Generate a new Packet object
      const rawPacket = generator.generate();

      // Position the packet at a random vertical height (10% to 80% down the screen)
      rawPacket.laneY = Math.floor(Math.random() * 70) + 10;
      
      // Add the packet to the screen immediately as "INCOMING"
      setPackets((prev) => [...prev, rawPacket]);

      // --- The Processing Timeline ---
      // 1. Packet travels for 1.5 seconds (reaching the firewall gate in the center)
      setTimeout(() => {
        // Run the packet through the OOP Firewall Engine!
        const processedPacket = engine.process(rawPacket);

        // Update stats depending on the result
        setStats((prev) => {
          const isMalicious = processedPacket.matchedRule.reason === "Malicious Signature Detected";
          return {
            allowed: prev.allowed + (processedPacket.status === "ALLOWED" ? 1 : 0),
            blocked: prev.blocked + (processedPacket.status === "BLOCKED" ? 1 : 0),
            threats: prev.threats + (isMalicious ? 1 : 0),
          };
        });

        // Update the log list in React state
        setLogs([...engine.logs]);

        // Update the packet status so CSS changes its color (Red or Green)
        setPackets((prev) =>
          prev.map((p) => (p.id === processedPacket.id ? processedPacket : p))
        );
      }, 1500); // 1.5s matches when the packet reaches the 50% line

      // 2. After 3 seconds, the packet finishes its screen travel, remove it from DOM
      setTimeout(() => {
        setPackets((prev) => prev.filter((p) => p.id !== rawPacket.id));
      }, 3000);

    }, 1500);

    return () => clearInterval(interval);
  }, [isSimulating]);

  // =====================================================================
  // 3. User Actions (Adding / Deleting Rules)
  // =====================================================================
  const handleAddRule = (e) => {
    e.preventDefault();
    // Add rule to the OOP Engine
    engine.addRule(formAction, formProtocol, formIp, formPort);
    // Sync React state with the updated rules list
    setRules([...engine.rules]);
    // Reset form defaults
    setFormIp("ANY");
    setFormPort("ANY");
  };

  const handleDeleteRule = (id) => {
    // Remove rule from the OOP Engine
    engine.deleteRule(id);
    // Sync React state
    setRules([...engine.rules]);
  };

  // =====================================================================
  // 4. Render Interface (HTML5 structure)
  // =====================================================================
  return (
    <div className="dashboard">
      
      {/* COLUMN 1: FIREWALL CONTROL PANEL */}
      <div className="panel">
        <h2>🛡️ Rule Controller</h2>
        
        <div className="rule-list">
          {rules.map((rule) => (
            <div key={rule.id} className={`rule-item ${rule.action.toLowerCase()}`}>
              <div className="rule-info">
                <strong>{rule.action}</strong> {rule.protocol} <br />
                IP: <code>{rule.sourceIp}</code> | Port: <code>{rule.port}</code>
              </div>
              {rule.id !== 2 && ( // Make the default allow rule permanent
                <button className="btn-delete" onClick={() => handleDeleteRule(rule.id)}>×</button>
              )}
            </div>
          ))}
        </div>

        {/* Form to add custom rules */}
        <form className="rule-form" onSubmit={handleAddRule}>
          <h3>Add Policy</h3>
          <select value={formAction} onChange={(e) => setFormAction(e.target.value)}>
            <option value="BLOCK">BLOCK</option>
            <option value="ALLOW">ALLOW</option>
          </select>
          <select value={formProtocol} onChange={(e) => setFormProtocol(e.target.value)}>
            <option value="ANY">Protocol: ANY</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
          <input 
            type="text" 
            placeholder="IP Source (e.g. 8.8.8.8 or ANY)" 
            value={formIp} 
            onChange={(e) => setFormIp(e.target.value)} 
            required 
          />
          <input 
            type="text" 
            placeholder="Port (e.g. 80 or ANY)" 
            value={formPort} 
            onChange={(e) => setFormPort(e.target.value)} 
            required 
          />
          <button className="btn-primary" type="submit">Apply Rule</button>
        </form>
      </div>

      {/* COLUMN 2: SIMULATION ARENA */}
      <div className="panel arena">
        <h2>⚡ Live Traffic Simulator</h2>
        <div style={{ display: "flex", gap: "10px" }}>
          <button className="btn-primary" onClick={() => setIsSimulating(!isSimulating)}>
            {isSimulating ? "⏸️ Pause Simulator" : "▶️ Play Simulator"}
          </button>
          <button className="btn-primary" onClick={() => {
            setStats({ allowed: 0, blocked: 0, threats: 0 });
            setLogs([]);
            engine.logs = [];
          }}>
            🧹 Clear Dashboard
          </button>
        </div>

        {/* The visual network area */}
        <div className="simulation-window">
          {/* Central Security Gateway Gate */}
          <div className="firewall-gateway">
            <span className="gateway-badge">NetShield Core</span>
          </div>

          {/* Render moving packet nodes */}
          {packets.map((packet) => (
            <div
              key={packet.id}
              className={`packet-node ${packet.status.toLowerCase()}`}
              style={{ top: `${packet.laneY}%` }}
            >
              <div><strong>ID:</strong> {packet.id} | {packet.protocol}</div>
              <div><code>{packet.sourceIp}:{packet.port}</code></div>
              <div style={{ fontSize: "0.65rem", opacity: 0.8, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {packet.payload}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* COLUMN 3: LIVE LOGS & CYBER MONITOR */}
      <div className="panel">
        <h2>📊 Threat Activity Log</h2>
        
        {/* Real-time statistics counters */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", marginBottom: "15px" }}>
          <div style={{ padding: "10px", backgroundColor: "#0e2415", border: "1px solid var(--neon-green)", borderRadius: "4px", textAlign: "center" }}>
            <span style={{ fontSize: "0.8rem", color: "#ccc" }}>Passed</span>
            <div style={{ fontSize: "1.5rem", color: var(--neon-green), fontWeight: "bold" }}>{stats.allowed}</div>
          </div>
          <div style={{ padding: "10px", backgroundColor: "#2b0d10", border: "1px solid var(--neon-red)", borderRadius: "4px", textAlign: "center" }}>
            <span style={{ fontSize: "0.8rem", color: "#ccc" }}>Blocked</span>
            <div style={{ fontSize: "1.5rem", color: var(--neon-red), fontWeight: "bold" }}>{stats.blocked}</div>
          </div>
        </div>

        {stats.threats > 0 && (
          <div className="alert-glow" style={{ padding: "10px", backgroundColor: "#4a0006", border: "1px solid var(--neon-red)", color: "white", borderRadius: "4px", textAlign: "center", fontWeight: "bold", fontSize: "0.85rem", marginBottom: "15px" }}>
            ⚠️ {stats.threats} MALICIOUS INTENDED ATTACK(S) PREVENTED
          </div>
        )}

        {/* Live Scrollable Logs */}
        <div className="log-list">
          {logs.map((log, index) => (
            <div key={index} className={`log-item ${log.packet.status.toLowerCase()}`}>
              <div>
                <strong>[{log.packet.status}]</strong> Packet #{log.packet.id} <br />
                <code>{log.packet.sourceIp}:{log.packet.port}</code> → {log.packet.destinationIp}
              </div>
              <div style={{ fontSize: "0.75rem", color: "#aaa", marginTop: "5px" }}>
                Rule Triggered: <em>{log.rule.action === "BLOCK" && log.rule.reason ? log.rule.reason : `Rule ID #${log.rule.id}`}</em>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}

// Render the App component into the HTML root element
const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);