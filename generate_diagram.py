#!/usr/bin/env python3
"""Generate TKS Fleet Architecture Excalidraw diagram."""
import json, os

seed_counter = 1000

def next_seed():
    global seed_counter
    seed_counter += 1
    return seed_counter

def rect(id, x, y, w, h, stroke, bg, gids=None, sw=2):
    s = next_seed()
    return {"id":id,"type":"rectangle","x":x,"y":y,"width":w,"height":h,
        "angle":0,"strokeColor":stroke,"backgroundColor":bg,
        "fillStyle":"solid","strokeWidth":sw,"strokeStyle":"solid",
        "roughness":1,"opacity":100,"groupIds":gids or [],"frameId":None,
        "roundness":{"type":3},"seed":s,"version":1,"versionNonce":s+5000,
        "isDeleted":False,"boundElements":[],"updated":1712534400000,
        "link":None,"locked":False}

def txt(id, x, y, w, h, content, fs, color="#1b1b1f", gids=None, align="center", ff=1):
    s = next_seed()
    return {"id":id,"type":"text","x":x,"y":y,"width":w,"height":h,
        "angle":0,"strokeColor":color,"backgroundColor":"transparent",
        "fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid",
        "roughness":1,"opacity":100,"groupIds":gids or [],"frameId":None,
        "roundness":None,"seed":s,"version":1,"versionNonce":s+5000,
        "isDeleted":False,"boundElements":[],"updated":1712534400000,
        "link":None,"locked":False,
        "text":content,"fontSize":fs,"fontFamily":ff,
        "textAlign":align,"verticalAlign":"top",
        "containerId":None,"originalText":content,"lineHeight":1.25}

def arrow(id, x, y, pts, stroke, dash=False, sw=2):
    s = next_seed()
    xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
    return {"id":id,"type":"arrow","x":x,"y":y,
        "width":max(max(xs)-min(xs),1),"height":max(max(ys)-min(ys),1),
        "angle":0,"strokeColor":stroke,"backgroundColor":"transparent",
        "fillStyle":"solid","strokeWidth":sw,
        "strokeStyle":"dashed" if dash else "solid",
        "roughness":1,"opacity":100,"groupIds":[],"frameId":None,
        "roundness":{"type":2},"seed":s,"version":1,"versionNonce":s+5000,
        "isDeleted":False,"boundElements":[],"updated":1712534400000,
        "link":None,"locked":False,
        "points":pts,"lastCommittedPoint":None,
        "startBinding":None,"endBinding":None,
        "startArrowhead":None,"endArrowhead":"arrow"}

els = []

# ──────────── LAYER LABELS ────────────
els.append(txt("lbl_l0", 60, 52, 200, 14, "LAYER 0", 11, "#94a3b8", align="left"))
els.append(txt("lbl_l1", 60, 167, 200, 14, "LAYER 1", 11, "#94a3b8", align="left"))
els.append(txt("lbl_l2", 60, 335, 200, 14, "LAYER 2", 11, "#94a3b8", align="left"))
els.append(txt("lbl_l3", 60, 530, 200, 14, "LAYER 3", 11, "#94a3b8", align="left"))

# ──────────── TITLE ────────────
els.append(txt("title", 300, 8, 630, 35, "TKS Agent Fleet Architecture", 28, "#1b1b1f"))

# ──────────── ROOT CONFIG ────────────
els.append(rect("root_box", 315, 60, 600, 55, "#6366f1", "#e3e2fe"))
els.append(txt("root_t1", 315, 65, 600, 23,
    "CLAUDE.md \u2014 Fleet Configuration", 18, "#312e81"))
els.append(txt("root_t2", 315, 90, 600, 14,
    "Anti-Autonomy | Proposal Loop | Strike Protocol | Token Discipline", 11, "#6366f1"))

# ──────────── tksButler ────────────
els.append(rect("butler_box", 365, 180, 500, 65, "#7c3aed", "#e8d5ff"))
els.append(txt("butler_t1", 365, 185, 500, 28, "tksButler", 22, "#4c1d95"))
els.append(txt("butler_t2", 365, 215, 500, 16,
    "Orchestrator & Engagement Manager", 13, "#6d28d9"))

# Butler skills
for i, sk in enumerate(["/hawkeye", "/maestro", "/handoff", "/archive", "/absorb"]):
    sx = 310 + i * 125
    els.append(rect(f"sk{i}_b", sx, 265, 110, 30, "#7c3aed", "#f3e8ff", sw=1))
    els.append(txt(f"sk{i}_t", sx, 270, 110, 20, sk, 13, "#6d28d9"))

# ──────────── SPECIALIST AGENTS ────────────
agents = [
    {"id":"bh","name":"bountyHunter","role":"Bug Bounty | P1-P4",
     "skills":"/hunt /brief /robin\n/save /absorb","triad":"[Stack + Logic + Feature]",
     "s":"#dc2626","bg":"#fecaca","tc":"#7f1d1d","x":50},
    {"id":"wa","name":"webApiPen","role":"Web/API | OWASP",
     "skills":"/work /robin\n/save /absorb","triad":"[Stack + Endpoint + Vector]",
     "s":"#ea580c","bg":"#fed7aa","tc":"#7c2d12","x":280},
    {"id":"np","name":"netPen","role":"Network & AD | Red Team",
     "skills":"/work /enum /robin\n/save /absorb","triad":"[OS + Protocol + Config]",
     "s":"#2563eb","bg":"#bfdbfe","tc":"#1e3a8a","x":510},
    {"id":"cp","name":"cloudPen","role":"Cloud | AWS/Azure/GCP",
     "skills":"/work /robin\n/save /absorb","triad":"[Provider + Service + Misconfig]",
     "s":"#0891b2","bg":"#a5f3fc","tc":"#164e63","x":740},
    {"id":"ctf","name":"ctfPlayer","role":"CTF & Pro Labs",
     "skills":"/solve /robin\n/save /absorb","triad":"[OS + Route + Feature]",
     "s":"#16a34a","bg":"#bbf7d0","tc":"#14532d","x":970},
]

for a in agents:
    g = [f"g_{a['id']}"]
    ax, aw = a["x"], 210
    els.append(rect(f"{a['id']}_b", ax, 360, aw, 110, a["s"], a["bg"], g))
    els.append(txt(f"{a['id']}_n", ax, 367, aw, 20, a["name"], 16, a["tc"], g))
    els.append(txt(f"{a['id']}_r", ax, 390, aw, 14, a["role"], 11, a["s"], g))
    els.append(txt(f"{a['id']}_sk", ax, 410, aw, 26, a["skills"], 10, a["tc"], g))
    els.append(txt(f"{a['id']}_tr", ax, 443, aw, 13, a["triad"], 10, a["s"], g))

# ──────────── KNOWLEDGE BASE ────────────
els.append(rect("pb_box", 150, 545, 400, 65, "#d97706", "#fef3c7"))
els.append(txt("pb_t1", 150, 550, 400, 23, "Playbooks", 18, "#78350f"))
els.append(txt("pb_t2", 150, 575, 400, 14,
    "AD | C2 | Cloud | Linux | Pivoting | Web | Windows", 11, "#92400e"))

els.append(rect("lr_box", 650, 545, 400, 65, "#9333ea", "#f3e8ff"))
els.append(txt("lr_t1", 650, 550, 400, 23, "Learnings (Global Brain)", 18, "#581c87"))
els.append(txt("lr_t2", 650, 575, 400, 14,
    "cloud.md | ctf.md | general.md | network.md | web.md", 11, "#6b21a8"))

# ──────────── PROPOSAL LOOP ────────────
els.append(rect("loop_box", 100, 670, 1030, 55, "#475569", "#f1f5f9"))
els.append(txt("loop_t1", 100, 674, 1030, 20,
    "Proposal Loop (Human-in-the-Loop)", 16, "#1e293b"))
els.append(txt("loop_t2", 100, 698, 1030, 15,
    "Analyze  \u2192  Propose  \u2192  HALT  \u2192  User Approves  \u2192  Execute  \u2192  Evaluate", 12, "#475569"))

# ──────────── ARROWS ────────────
# Root -> Butler
els.append(arrow("a_rb", 615, 115, [[0,0],[0,65]], "#6366f1"))

# Butler -> Agents (fan from skills bottom to agent tops)
for i, cx in enumerate([155, 385, 615, 845, 1075]):
    els.append(arrow(f"a_ba{i}", 615, 300, [[0,0],[cx-615,60]], "#7c3aed", dash=True))

# Agents -> Playbooks (left side of agent row)
els.append(arrow("a_pb", 350, 470, [[0,0],[0,75]], "#d97706"))
# Agents -> Learnings (right side of agent row)
els.append(arrow("a_lr", 850, 470, [[0,0],[0,75]], "#9333ea"))

# Annotations
els.append(txt("ann_pb", 360, 498, 120, 14, "reads", 11, "#d97706"))
els.append(txt("ann_lr", 860, 498, 150, 14, "reads & writes", 11, "#9333ea"))

# ──────────── OUTPUT ────────────
diagram = {
    "type": "excalidraw",
    "version": 2,
    "source": "https://excalidraw.com",
    "elements": els,
    "appState": {"gridSize": None, "viewBackgroundColor": "#ffffff"},
    "files": {}
}

out = os.path.join(os.path.dirname(__file__), "fleet_architecture.excalidraw")
with open(out, "w") as f:
    json.dump(diagram, f, indent=2)
print(f"Generated {len(els)} elements -> {out}")
