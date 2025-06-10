import requests
import os
import time
import socket
import json
import platform
import subprocess
import folium
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

ASCII_ART = """
███████╗██╗  ██╗██╗██████╗ 
██╔════╝██║  ██║██║██╔══██╗
███████╗███████║██║██████╔╝
╚════██║██╔══██║██║██╔═══╝ 
███████║██║  ██║██║██║     
╚══════╝╚═╝  ╚═╝╚═╝╚═╝     
   Skid IP Scanner Tool [v1.0]
"""

ABUSE_API_KEY = "e06563cefc87ef8345e30855201f83e62e3823700276ce2a4368a40110145ea057274eb108887352"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    console.print(Text(ASCII_ART, style="bold green"))
    console.print(Text("🔍 IP Lookup, Ping, DNS, Abuse Check, Webhook Discord, Map, History, Skid CLI\n", style="grey50"))

def main_menu():
    print_banner()
    table = Table(title="Menu Principal", title_style="bold magenta")
    table.add_column("Option", style="cyan", no_wrap=True)
    table.add_column("Action", style="white")

    table.add_row("1", "Scanner une IP")
    table.add_row("2", "Scanner mon IP publique")
    table.add_row("3", "Afficher l'historique")
    table.add_row("4", "Quitter")

    console.print(table)
    return Prompt.ask("💡 Choisis une option", choices=["1", "2", "3", "4"], default="1")

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text.strip()
    except:
        return None

def resolve_reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        return host
    except:
        return "Non résolu"

def ping_ip(ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", ip]
        output = subprocess.check_output(command, stderr=subprocess.DEVNULL).decode()
        if "time=" in output:
            ms = output.split("time=")[-1].split()[0]
            return f"Actif ({ms})"
        return "Inactif"
    except:
        return "Inactif"
def ip_lookup(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=66846719"
        r = requests.get(url).json()
        if r["status"] != "success":
            return None

        return {
            "IP": r["query"],
            "Pays": r["country"],
            "Région": r["regionName"],
            "Ville": r["city"],
            "Code Postal": r["zip"],
            "Latitude": r["lat"],
            "Longitude": r["lon"],
            "Fuseau horaire": r["timezone"],
            "FAI": r["isp"],
            "ASN": r["as"],
            "Mobile": str(r["mobile"]),
            "Proxy / VPN": str(r["proxy"]),
            "Hébergement": str(r["hosting"])
        }
    except:
        return None

def check_abuse_ipdb(ip):
    try:
        headers = {
            "Key": ABUSE_API_KEY,
            "Accept": "application/json"
        }
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", headers=headers)
        data = response.json()["data"]
        return {
            "Abus détectés": data["totalReports"],
            "Score": f"{data['abuseConfidenceScore']}%",
            "Dernier rapport": data["lastReportedAt"] or "Aucun"
        }
    except:
        return {
            "Abus détectés": "Erreur",
            "Score": "Erreur",
            "Dernier rapport": "Erreur"
        }

def analyse_contexte(ipinfo):
    infos = []
    if ipinfo["Proxy / VPN"] == "True":
        infos.append("⚠️ IP probablement derrière un proxy ou VPN.")
    if ipinfo["Hébergement"] == "True":
        infos.append("☁️ IP hébergée (probablement serveur/Cloud).")
    if "google" in ipinfo["FAI"].lower() or "amazon" in ipinfo["FAI"].lower():
        infos.append("💡 L'IP semble appartenir à un hébergeur cloud (Google, AWS...)")
    if not infos:
        infos.append("✅ Aucun comportement suspect détecté.")
    return infos

def port_scan(ip, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]):
    results = {}
    for port in ports:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect((ip, port))
            results[port] = "✅ Ouvert"
        except:
            results[port] = "❌ Fermé"
        s.close()
    return results

def create_map(ipinfo):
    try:
        lat, lon = ipinfo["Latitude"], ipinfo["Longitude"]
        fmap = folium.Map(location=[lat, lon], zoom_start=10)
        folium.Marker([lat, lon], tooltip=ipinfo["IP"]).add_to(fmap)
        map_path = f"map_{ipinfo['IP'].replace('.', '_')}.html"
        fmap.save(map_path)
        return map_path
    except:
        return None
def save_history(ip, ipinfo, abuse, context, ports):
    if not os.path.isdir("logs"):
        os.mkdir("logs")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logname = f"logs/{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(logname, "w", encoding="utf-8") as f:
        f.write(f"[SCAN - {now}]\n\n")
        for k, v in ipinfo.items():
            f.write(f"{k}: {v}\n")
        f.write("\n--- AbuseIPDB ---\n")
        for k, v in abuse.items():
            f.write(f"{k}: {v}\n")
        f.write("\n--- Analyse ---\n")
        for msg in context:
            f.write(f"- {msg}\n")
        f.write("\n--- Ports ---\n")
        for p, status in ports.items():
            f.write(f"Port {p}: {status}\n")
    return logname

def show_results(ipinfo, abuse, context, ports, dns, latency):
    console.print(Panel.fit(Text(f"📍 Infos IP : {ipinfo['IP']}", style="bold cyan"), title="🎯 Résultat IP"))

    for key, val in ipinfo.items():
        console.print(f"[bold white]{key}[/bold white] : {val}")

    console.print(f"[bold white]DNS (Reverse)[/bold white] : {dns}")
    console.print(f"[bold white]Ping[/bold white] : {latency}")

    console.print("\n[bold yellow]🛡️ AbuseIPDB[/bold yellow]")
    for k, v in abuse.items():
        console.print(f"[cyan]{k}[/cyan] : {v}")

    console.print("\n[bold magenta]💬 Analyse contextuelle[/bold magenta]")
    for line in context:
        console.print(f"[white]- {line}[/white]")

    console.print("\n[bold green]📡 Scan des ports[/bold green]")
    for p, status in ports.items():
        color = "green" if "Ouvert" in status else "red"
        console.print(f"[bold white]Port {p}[/bold white] : [{color}]{status}[/{color}]")
def ask_webhook():
    webhook = Prompt.ask(Text("🔗 Webhook Discord (laisser vide pour ignorer)", style="grey50"))
    if webhook.startswith("https://discord.com/api/webhooks/"):
        return webhook
    return None

def send_to_discord(webhook, ipinfo, abuse, filepath):
    if not webhook or not os.path.isfile(filepath):
        return

    embed = {
        "title": f"🔍 Scan IP - {ipinfo['IP']}",
        "fields": [],
        "footer": {"text": "Skid IP Scanner"},
        "color": 5763719,
        "timestamp": datetime.utcnow().isoformat()
    }

    for k, v in ipinfo.items():
        embed["fields"].append({"name": k, "value": str(v), "inline": True})

    for k, v in abuse.items():
        embed["fields"].append({"name": f"Abuse - {k}", "value": str(v), "inline": True})

    files = {'file': (os.path.basename(filepath), open(filepath, 'rb'))}
    payload = {"embeds": [embed]}

    try:
        res = requests.post(webhook, data={"payload_json": json.dumps(payload)}, files=files)
        if res.status_code in [200, 204]:
            console.print("[green]✅ Envoyé au webhook Discord.[/green]")
        else:
            console.print(f"[red]❌ Erreur Webhook : {res.status_code}[/red]")
    except Exception as e:
        console.print(f"[red]💥 Erreur d'envoi : {e}[/red]")
def scan_target(ip):
    ipinfo = ip_lookup(ip)
    if not ipinfo:
        console.print("[red]IP invalide ou échec de récupération.[/red]")
        return

    abuse = check_abuse_ipdb(ip)
    context = analyse_contexte(ipinfo)
    dns = resolve_reverse_dns(ip)
    latency = ping_ip(ip)
    ports = port_scan(ip)
    show_results(ipinfo, abuse, context, ports, dns, latency)

    filepath = save_history(ip, ipinfo, abuse, context, ports)
    map_path = create_map(ipinfo)
    if map_path:
        console.print(f"[blue]🌍 Carte enregistrée : {map_path}[/blue]")

    webhook = ask_webhook()
    if webhook:
        send_to_discord(webhook, ipinfo, abuse, filepath)

def show_history():
    if not os.path.isdir("logs"):
        console.print("[yellow]Aucun historique trouvé.[/yellow]")
        return

    files = os.listdir("logs")
    if not files:
        console.print("[yellow]Aucun fichier dans logs/[/yellow]")
        return

    table = Table(title="Historique de scans")
    table.add_column("Fichier", style="cyan")
    for f in files:
        table.add_row(f)
    console.print(table)

def run():
    while True:
        choice = main_menu()
        if choice == "1":
            ip = Prompt.ask("🔎 Adresse IP à scanner")
            scan_target(ip)
        elif choice == "2":
            ip = get_public_ip()
            if ip:
                console.print(f"[bold green]🌐 IP publique détectée : {ip}[/bold green]")
                scan_target(ip)
            else:
                console.print("[red]Impossible de récupérer l'IP publique[/red]")
        elif choice == "3":
            show_history()
        elif choice == "4":
            break
        input("\n[grey50]Appuie sur Entrée pour retourner au menu...[/grey50]")

if __name__ == "__main__":
    run()
    