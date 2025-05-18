from scapy.all import rdpcap, TCP
import json
from datetime import datetime

# Charger les règles attendues depuis un fichier JSON
with open("modbus_rules.json", "r") as f:
    rules = json.load(f)

# Charger le .pcap à analyser
packets = rdpcap("ModbusTCP.pcap")
alerts = []

for pkt in packets:
    if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
        raw = bytes(pkt[TCP].payload)
        if len(raw) > 7:
            func_code = raw[7]
            src = pkt[0][1].src
            dst = pkt[0][1].dst

            # Vérification du comportement autorisé
            authorized_funcs = rules.get(src, [])
            if str(func_code) not in authorized_funcs:
                alert = {
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src": src,
                    "dst": dst,
                    "func_code": func_code,
                    "level": "CRITIQUE" if func_code in [5, 6, 15, 16] else "AVERTISSEMENT",
                    "message": f"Fonction Modbus non autorisée détectée : code {func_code} de {src} vers {dst}"
                }
                alerts.append(alert)

# Enregistrer les alertes dans un fichier log
with open("alerts.log", "w") as log:
    for a in alerts:
        log.write(f"[{a['time']}] [{a['level']}] {a['message']}\n")

# ➕ Affichage d’un résumé final clair
total_alerts = len(alerts)
critical_count = sum(1 for a in alerts if a["level"] == "CRITIQUE")
unique_ips = set(a["src"] for a in alerts)

print(f"\n✅ Analyse terminée : {total_alerts} alertes détectées "
      f"(dont {critical_count} critiques) | {len(unique_ips)} IPs sources impliquées")