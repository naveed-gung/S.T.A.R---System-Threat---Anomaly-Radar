import React, { useState, useEffect, useRef } from 'react';

const App = () => {
    const [status, setStatus] = useState("DISCONNECTED");
    const [events, setEvents] = useState([]);
    const [threatLevel, setThreatLevel] = useState("LOW");
    const logEndRef = useRef(null);

    const scrollToBottom = () => {
        logEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [events]);

    const scrambleTo = (text) => {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
        let iterations = 0;
        const interval = setInterval(() => {
            setStatus(text.split("").map((letter, index) => {
                if (index < iterations) {
                    return text[index];
                }
                return chars[Math.floor(Math.random() * chars.length)];
            }).join(""));

            if (iterations >= text.length) {
                clearInterval(interval);
                setStatus(text); // Ensure final set is clean
            }
            iterations += 1 / 2; // Slower speed
        }, 50);
    };

    useEffect(() => {
        // Connect to Electron IPC via preload script
        if (window.starAPI) {
            // Request initial status
            console.log("App: Requesting status...");
            window.starAPI.requestStatus();

            window.starAPI.onEvent((event, message) => {
                console.log("App Received:", message);

                let type = "INFO";
                if (typeof message === 'string') {
                    if (message.includes("[ALERT]")) type = "CRITICAL";
                    if (message.includes("Suspicious")) type = "WARNING";

                    if (type === "CRITICAL") setThreatLevel("HIGH");

                    // Only add to log if it's not a status update
                    if (!message.includes("Connected") && !message.includes("Disconnected")) {
                        // Keep only last 100 events
                        setEvents(prev => [...prev.slice(-99), {
                            timestamp: new Date().toLocaleTimeString(),
                            text: message,
                            type: type
                        }]);
                    }

                    if (message.includes("Connected")) {
                        if (status !== "ONLINE") scrambleTo("ONLINE");
                    } else if (message.includes("Disconnected")) {
                        setStatus("DISCONNECTED");
                    }
                }
            });
        }
    }, []); // eslint-disable-next-line react-hooks/exhaustive-deps

    return (
        <div className="dashboard">
            <div className="scanlines"></div>

            <header className="header">
                <div>
                    <h1 className="glow-text">S.T.A.R. DAEMON</h1>
                    <small>SYSTEM THREAT & ANOMALY RADAR</small>
                </div>
                <div style={{ textAlign: 'right' }}>
                    {!window.starAPI && <div className="critical">⚠ BROWSER MODE (NO API)</div>}
                    <div className={status === "ONLINE" ? "glow-text" : "critical"}>
                        STATUS: {status}
                    </div>
                    <div className={threatLevel === "HIGH" ? "critical" : "glow-text"}>
                        THREAT LEVEL: {threatLevel}
                    </div>
                </div>
            </header>

            <aside className="sidebar">
                <div className="radar-container">
                    <div className="radar-sweep"></div>
                </div>

                <h3>SYSTEM METRICS</h3>
                <div>MEM: VALIDATING...</div>
                <div>CPU: MONITORING...</div>
                <div>NET: SECURE</div>

                <br />
                <h3>ACTIVE FILTERS</h3>
                <div>[X] JIT COMPILERS</div>
                <div>[X] SIGNED BINARIES</div>
                <div>[ ] HEURISTIC SCAN</div>
            </aside>

            <main className="main-content">
                <h3>TACTICAL LOG</h3>
                <div className="log-container">
                    {events.length === 0 && <div style={{ opacity: 0.5 }}>Waiting for telemetry...</div>}
                    {events.map((ev, i) => (
                        <div key={i} className={`log-entry ${ev.type === 'CRITICAL' ? 'critical' : ev.type === 'WARNING' ? 'warning' : ''}`}>
                            <span style={{ opacity: 0.7 }}>[{ev.timestamp}]</span> {ev.text}
                        </div>
                    ))}
                    <div ref={logEndRef} />
                </div>
            </main>

            <footer className="footer">
                <a href="https://github.com/naveed-gung" target="_blank" rel="noopener noreferrer" title="GitHub">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.79 24 17.3 24 12c0-6.63-5.37-12-12-12z" />
                    </svg>
                </a>
                <a href="https://naveed-gung.dev" target="_blank" rel="noopener noreferrer" title="Portfolio">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="2" y1="12" x2="22" y2="12"></line>
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                    </svg>
                </a>
            </footer>
        </div>
    );
};

export default App;
