#!/usr/bin/env python3
"""
Generate visual outputs — SVG, PNG, HTML.

Saves to ./visualizations/ folder.
"""

import json
import os
import sqlite3
from datetime import datetime

# Try to import visualization libraries
HAS_GRAPHVIZ = False  # Skip graphviz for now - requires system binary

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import networkx as nx
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("ERROR: matplotlib not available. Install with: pip install matplotlib networkx")


def main():
    db_path = "network_snapshot.db"

    if not os.path.exists(db_path):
        print("ERROR: network_snapshot.db not found. Run inspect_network.py first.")
        return

    # Create output directory
    output_dir = "visualizations"
    os.makedirs(output_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get data
    cursor.execute("SELECT receipt_id, provider, price, provenance_depth, timestamp FROM receipts ORDER BY timestamp")
    receipts = cursor.fetchall()

    cursor.execute("SELECT child_id, parent_id, relationship FROM dag_edges")
    dag_edges = cursor.fetchall()

    cursor.execute("SELECT voucher, vouchee, amount, timestamp FROM vouches")
    vouches = cursor.fetchall()

    # Build agent map
    cursor.execute("SELECT DISTINCT provider FROM receipts")
    providers = [r[0] for r in cursor.fetchall()]

    agent_names = {}
    names = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon"]
    for i, provider in enumerate(providers):
        agent_names[provider] = names[i] if i < len(names) else f"Agent{i}"

    receipt_map = {}
    for rid, provider, price, depth, timestamp in receipts:
        receipt_map[rid] = {
            "provider": provider,
            "agent": agent_names.get(provider, "???"),
            "price": price,
            "depth": depth,
            "timestamp": timestamp,
        }

    print(f"Generating visualizations in {output_dir}/...")

    # ═══════════════════════════════════════════════════════════════
    # 1. PROVENANCE DAG (Matplotlib + NetworkX)
    # ═══════════════════════════════════════════════════════════════

    if HAS_MATPLOTLIB:
        print("  [1/5] Provenance DAG...")

        G = nx.DiGraph()

        # Add nodes
        for rid, info in receipt_map.items():
            G.add_node(rid[:8], agent=info['agent'], price=info['price'], depth=info['depth'])

        # Add edges
        for child, parent, relationship in dag_edges:
            G.add_edge(parent[:8], child[:8], relationship=relationship)

        fig, ax = plt.subplots(figsize=(12, 8))

        # Use hierarchical layout
        try:
            pos = nx.spring_layout(G, k=2, iterations=50)
        except:
            pos = nx.shell_layout(G)

        # Node colors based on depth
        node_colors = []
        for node in G.nodes():
            depth = receipt_map[[k for k in receipt_map.keys() if k.startswith(node)][0]]['depth']
            node_colors.append('lightblue' if depth == 0 else 'lightgreen')

        # Draw
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=3000,
                              alpha=0.9, ax=ax)

        nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True,
                              arrowsize=20, arrowstyle='->', ax=ax)

        # Labels
        labels = {}
        for node in G.nodes():
            full_rid = [k for k in receipt_map.keys() if k.startswith(node)][0]
            info = receipt_map[full_rid]
            labels[node] = f"{info['agent']}\n{node}\n${info['price']/100:.0f}"

        nx.draw_networkx_labels(G, pos, labels, font_size=9, ax=ax)

        ax.set_title('Provenance DAG', fontsize=16, fontweight='bold')
        ax.axis('off')

        plt.tight_layout()
        plt.savefig(f"{output_dir}/provenance_dag.png", dpi=150, bbox_inches='tight', facecolor='white')
        plt.close()
        print(f"      → {output_dir}/provenance_dag.png")

    # ═══════════════════════════════════════════════════════════════
    # 2. TRUST SCORES (Matplotlib)
    # ═══════════════════════════════════════════════════════════════

    if HAS_MATPLOTLIB:
        print("  [2/5] Trust scores...")

        transaction_value = 5000

        agents = []
        stakes = []
        quotients = []
        colors = []

        for agent in sorted(set(agent_names.values())):
            # Calculate stake
            agent_receipts = [r for r in receipts if agent_names.get(r[1]) == agent]
            direct = sum(r[2] for r in agent_receipts)

            vouches_received = [v for v in vouches if agent_names.get(v[1]) == agent]
            vouched = sum(v[2] for v in vouches_received)

            stake = direct + vouched
            quotient = stake / transaction_value if transaction_value > 0 else 0

            agents.append(agent)
            stakes.append(stake / 100)
            quotients.append(quotient)

            # Color based on recommendation
            if quotient >= 50:
                colors.append('green')
            elif quotient >= 5:
                colors.append('orange')
            else:
                colors.append('red')

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # Stake bar chart
        ax1.barh(agents, stakes, color=colors)
        ax1.set_xlabel('Effective Stake ($)', fontsize=12)
        ax1.set_title('Agent Stakes', fontsize=14, fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)

        # Trust quotient bar chart
        ax2.barh(agents, quotients, color=colors)
        ax2.set_xlabel('Trust Quotient', fontsize=12)
        ax2.set_title(f'Trust for ${transaction_value/100:.0f} Transaction', fontsize=14, fontweight='bold')
        ax2.axvline(x=5, color='orange', linestyle='--', alpha=0.5, label='Escrow threshold')
        ax2.axvline(x=50, color='green', linestyle='--', alpha=0.5, label='Instant threshold')
        ax2.legend()
        ax2.grid(axis='x', alpha=0.3)

        # Legend
        red_patch = mpatches.Patch(color='red', label='Collateral required')
        orange_patch = mpatches.Patch(color='orange', label='Escrow')
        green_patch = mpatches.Patch(color='green', label='Instant')
        ax1.legend(handles=[red_patch, orange_patch, green_patch], loc='lower right')

        plt.tight_layout()
        plt.savefig(f"{output_dir}/trust_scores.png", dpi=150, bbox_inches='tight')
        plt.close()
        print(f"      → {output_dir}/trust_scores.png")

    # ═══════════════════════════════════════════════════════════════
    # 3. TIMELINE (Matplotlib)
    # ═══════════════════════════════════════════════════════════════

    if HAS_MATPLOTLIB:
        print("  [3/5] Timeline...")

        events = []

        for rid, provider, price, depth, timestamp in receipts:
            events.append({
                "time": timestamp,
                "type": "Receipt",
                "agent": agent_names.get(provider, "???"),
                "value": price,
                "label": f"{agent_names.get(provider, '???')}: ${price/100:.0f}",
            })

        for voucher, vouchee, amount, timestamp in vouches:
            events.append({
                "time": timestamp,
                "type": "Vouch",
                "agent": agent_names.get(voucher, "???"),
                "value": amount,
                "label": f"{agent_names.get(voucher, '???')} → {agent_names.get(vouchee, '???')}: ${amount/100:.0f}",
            })

        events.sort(key=lambda e: e["time"])

        fig, ax = plt.subplots(figsize=(12, 6))

        # Plot events
        times = [e["time"] for e in events]
        values = [e["value"] / 100 for e in events]
        colors_map = {
            "Receipt": "blue",
            "Vouch": "green",
        }
        colors = [colors_map[e["type"]] for e in events]

        scatter = ax.scatter(times, values, c=colors, s=200, alpha=0.6, edgecolors='black')

        # Annotate
        for i, e in enumerate(events):
            ax.annotate(e["label"], (e["time"], e["value"]/100),
                       xytext=(10, 10), textcoords='offset points',
                       fontsize=8, alpha=0.8)

        ax.set_xlabel('Time', fontsize=12)
        ax.set_ylabel('Value ($)', fontsize=12)
        ax.set_title('Network Timeline', fontsize=14, fontweight='bold')
        ax.grid(alpha=0.3)

        # Legend
        blue_patch = mpatches.Patch(color='blue', label='Receipt')
        green_patch = mpatches.Patch(color='green', label='Vouch')
        ax.legend(handles=[blue_patch, green_patch])

        plt.tight_layout()
        plt.savefig(f"{output_dir}/timeline.png", dpi=150, bbox_inches='tight')
        plt.close()
        print(f"      → {output_dir}/timeline.png")

    # ═══════════════════════════════════════════════════════════════
    # 4. AGENT NETWORK (Matplotlib + NetworkX)
    # ═══════════════════════════════════════════════════════════════

    if HAS_MATPLOTLIB:
        print("  [4/5] Agent network...")

        G = nx.DiGraph()

        # Build relationship counts
        relationships = {}
        for child, parent, relationship in dag_edges:
            child_agent = receipt_map[child]["agent"]
            parent_agent = receipt_map[parent]["agent"]

            key = (parent_agent, child_agent)
            relationships[key] = relationships.get(key, 0) + 1

        for voucher, vouchee, amount, timestamp in vouches:
            voucher_agent = agent_names.get(voucher, "???")
            vouchee_agent = agent_names.get(vouchee, "???")

            key = (voucher_agent, vouchee_agent)
            relationships[key] = relationships.get(key, 0) + 1

        # Add nodes and edges
        all_agents = set(agent_names.values())
        for agent in all_agents:
            agent_receipts = [r for r in receipts if agent_names.get(r[1]) == agent]
            receipt_count = len(agent_receipts)
            G.add_node(agent, count=receipt_count)

        for (from_agent, to_agent), count in relationships.items():
            G.add_edge(from_agent, to_agent, weight=count)

        fig, ax = plt.subplots(figsize=(10, 8))

        pos = nx.spring_layout(G, k=2, iterations=50)

        # Node sizes based on receipt count
        node_sizes = [G.nodes[node].get('count', 0) * 1000 + 1000 for node in G.nodes()]

        # Edge widths based on relationship count
        edge_widths = [G[u][v]['weight'] * 2 for u, v in G.edges()]

        nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color='lightblue',
                              alpha=0.8, ax=ax)

        nx.draw_networkx_edges(G, pos, width=edge_widths, edge_color='gray',
                              arrows=True, arrowsize=20, arrowstyle='->', ax=ax)

        # Labels
        labels = {node: f"{node}\n({G.nodes[node].get('count', 0)})" for node in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels, font_size=11, ax=ax)

        # Edge labels
        edge_labels = {(u, v): str(G[u][v]['weight']) for u, v in G.edges()}
        nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=9, ax=ax)

        ax.set_title('Agent Network', fontsize=16, fontweight='bold')
        ax.axis('off')

        plt.tight_layout()
        plt.savefig(f"{output_dir}/agent_network.png", dpi=150, bbox_inches='tight', facecolor='white')
        plt.close()
        print(f"      → {output_dir}/agent_network.png")

    # ═══════════════════════════════════════════════════════════════
    # 5. HTML DASHBOARD
    # ═══════════════════════════════════════════════════════════════

    print("  [5/5] HTML dashboard...")

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>VCR Network Visualization</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h1 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #444;
            border-bottom: 2px solid #007AFF;
            padding-bottom: 8px;
            margin-bottom: 20px;
        }}
        img {{
            max-width: 100%;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #007AFF;
        }}
        .stat-label {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: bold;
            color: #333;
            margin-top: 5px;
        }}
        .merkle {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>VCR Network Visualization</h1>
        <p class="subtitle">Cryptographically-verified agent compute network</p>

        <div class="stats">
            <div class="stat">
                <div class="stat-label">Agents</div>
                <div class="stat-value">{len(set(agent_names.values()))}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Receipts</div>
                <div class="stat-value">{len(receipts)}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Total Value</div>
                <div class="stat-value">${sum(r[2] for r in receipts)/100:.0f}</div>
            </div>
            <div class="stat">
                <div class="stat-label">DAG Edges</div>
                <div class="stat-value">{len(dag_edges)}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Vouches</div>
                <div class="stat-value">{len(vouches)}</div>
            </div>
        </div>

        <div class="section">
            <h2>Provenance DAG</h2>
            <p>Hash-linked receipts forming a directed acyclic graph. Each receipt cryptographically commits to its parents.</p>
            <img src="provenance_dag.png" alt="Provenance DAG">
        </div>

        <div class="section">
            <h2>Agent Network</h2>
            <p>Relationships between agents. Arrow thickness indicates interaction count.</p>
            <img src="agent_network.png" alt="Agent Network">
        </div>

        <div class="section">
            <h2>Trust Scores</h2>
            <p>Algorithmic trust computed from work history. Stake = direct value + vouched capital.</p>
            <img src="trust_scores.png" alt="Trust Scores">
        </div>

        <div class="section">
            <h2>Timeline</h2>
            <p>Chronological view of all network events.</p>
            <img src="timeline.png" alt="Timeline">
        </div>

        <div class="section">
            <h2>Merkle Root</h2>
            <p>All receipts are indexed in an append-only Merkle tree. Anyone can verify inclusion.</p>
            <div class="merkle">
Root: {cursor.execute("SELECT leaf_hash FROM entries").fetchall()[0][0].hex() if cursor.execute("SELECT COUNT(*) FROM entries").fetchone()[0] > 0 else "empty"}<br>
Size: {cursor.execute("SELECT COUNT(*) FROM entries").fetchone()[0]} entries
            </div>
        </div>

        <div class="section">
            <h2>How This Works</h2>
            <p><strong>Every claim is cryptographically verifiable:</strong></p>
            <ul>
                <li><strong>Identity:</strong> Ed25519 signatures prove who issued each receipt</li>
                <li><strong>Content:</strong> SHA-256 hashes bind input and output data</li>
                <li><strong>Provenance:</strong> Parent links form tamper-evident DAG</li>
                <li><strong>Inclusion:</strong> Merkle proofs show receipt is in the log</li>
                <li><strong>Trust:</strong> Stake computed algorithmically from public receipts</li>
            </ul>
            <p>No platform. No central authority. Just cryptographic math.</p>
        </div>

        <div class="section">
            <h2>Database</h2>
            <p>All data is stored in SQLite: <code>network_snapshot.db</code> ({os.path.getsize(db_path)} bytes)</p>
            <p>Query with: <code>sqlite3 network_snapshot.db "SELECT * FROM receipts"</code></p>
        </div>
    </div>
</body>
</html>
"""

    with open(f"{output_dir}/index.html", "w") as f:
        f.write(html)

    print(f"      → {output_dir}/index.html")

    print()
    print(f"✓ Done! Open {output_dir}/index.html in your browser.")
    print()

    conn.close()


if __name__ == "__main__":
    main()
