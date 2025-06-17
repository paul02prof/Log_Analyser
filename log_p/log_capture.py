import subprocess
import json
import pwd
from datetime import datetime
import requests
import time
import socket




LAST_SEND_FILE = "last_send.txt"
JSON_FILE = "logs_fusionnes.json"
URL = "http://127.0.0.1:8000/upload_json"  # Modifier selon l'adresse réelle

severity_map = {
    "0": "emergency", "1": "alert", "2": "critical", "3": "error",
    "4": "warning", "5": "notice", "6": "info", "7": "debug"
}
facility_map = {
    "0": "kern",
    "1": "user",
    "2": "mail",
    "3": "daemon",
    "4": "auth",
    "5": "syslog",
    "6": "lpr",
    "7": "news",
    "8": "uucp",
    "9": "clock",
    "10": "authpriv",
    "11": "ftp",
    "13": "audit",
    "14": "alert"
}
def read_last_send_timestamp():
    try:
        with open(LAST_SEND_FILE, 'r') as f:
            ts = float(f.read().strip())
            return ts
    except (FileNotFoundError, ValueError):
        return 0.0

def write_last_send_timestamp(ts: float):
    with open(LAST_SEND_FILE, 'w') as f:
        f.write(str(ts))

def get_local_ip():
    try:
        # Connexion à une IP externe pour déterminer l'IP locale utilisée
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def extract_journald_logs(last_send_ts):
    journal_logs = []
    max_timestamp = last_send_ts

    try:
        start_time_str = datetime.fromtimestamp(last_send_ts).strftime('%Y-%m-%d %H:%M:%S')
        result = subprocess.run(
            ["journalctl", "-o", "json", f"--since={start_time_str}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("Erreur journalctl:", e.stderr)
        return journal_logs, max_timestamp

    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        timestamp = int(entry.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000
        if timestamp <= last_send_ts:
            continue

        if timestamp > max_timestamp:
            max_timestamp = timestamp

        dt = datetime.fromtimestamp(timestamp)

        uid = entry.get("_UID", "")
        try:
            username = pwd.getpwuid(int(uid)).pw_name
        except Exception:
            username = "unknown"

        unit = entry.get("_SYSTEMD_UNIT", "N/A")
        ident = entry.get("SYSLOG_IDENTIFIER", entry.get("SYSLOG_FACILITY", "N/A"))
        facility = entry.get('SYSLOG_FACILITY')

        transport = entry.get('_TRANSPORT', '')

        categorie = facility_map[facility] if facility and facility in facility_map\
           else(
           "auth" if "auth" in ident.lower()
            else (
            "kern" if "kernel" in ident.lower() or "kern" in unit.lower() or "kern" in transport.lower()
            else (
                "dpkg" if "dpkg" in ident.lower() or "dpkg" in unit.lower() or "dpkg" in transport.lower()
            else (
                "audit" if "audit" in ident.lower() or "audit" in unit.lower() or "audit" in transport.lower()
            else (
                    "syslog" if "syslog" in ident.lower() or "syslog" in unit.lower() or "syslog" in transport.lower()
            else (
                        "daemon" if "daemon" in ident.lower()
            else (
                            "news" if "news" in ident.lower() or "news" in unit.lower() or "news" in transport.lower()
            else (
                                "clock" if "clock" in ident.lower() or "clock" in unit.lower() or "clock" in transport.lower()
                                else (
                                    "alert" if "alert" in ident.lower() or "alert" in unit.lower() or "alert" in transport.lower()
                                    else (
                                        "authpriv" if "authpriv" in ident.lower() or "authpriv" in unit.lower() or "authpriv" in transport.lower()
                                        else (
                                            "user" if "user" in ident.lower() or "user" in unit.lower() or "user" in transport.lower()

                                            else "system"
                ) ))))))))
            )
        )

        log = {
            "utilisateur_nom": username,
            "date": dt.strftime("%Y-%m-%d"),
            "heure": dt.strftime("%H:%M:%S"),
            "source": ident,
            "categorie_log": categorie,
            "pid": entry.get("_PID", "N/A"),
            "severite": severity_map.get(entry.get("PRIORITY", ""), "unknown"),
            "message": entry.get("MESSAGE", ""),
            "nom_machine": entry.get("_HOSTNAME", "N/A"),
            "service_systemd": unit
        }

        journal_logs.append(log)

    return journal_logs, max_timestamp

def extract_apt_logs(journ_logs):
    apt_logs = []
    apt_log_file = "/var/log/apt/history.log"
    try:
        with open(apt_log_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("⚠️ Fichier history.log introuvable.")
        return apt_logs

    log_entry = {}
    message = ""
    for line in lines:
        line = line.strip()

        if line.startswith("Start-Date:"):

            date_str = line.replace("Start-Date: ", "")
            dt = datetime.strptime(date_str, "%Y-%m-%d  %H:%M:%S")
            timestamp_journal = int(datetime.strptime(f"{journ_logs[0]["date"]} {journ_logs[0]["heure"]}",
                                                  "%Y-%m-%d %H:%M:%S").timestamp())

            timestamp_apt = int(datetime.strptime(f"{dt.strftime("%Y-%m-%d")} {dt.strftime("%H:%M:%S")}", "%Y-%m-%d %H:%M:%S").timestamp())
            if timestamp_apt >=timestamp_journal:
               log_entry = {
                "date": dt.strftime("%Y-%m-%d"),
                "heure": dt.strftime("%H:%M:%S"),
                "source": "apt",
                "categorie_log": "apt",
                "utilisateur_nom": "unknown",
                "pid": "N/A",
                "severite": "info",
                "message": "",
                "nom_machine": "localhost",
                "service_systemd": "N/A"
            }
            message = ""

        elif line.startswith("Commandline:"):
            message += f"Commande: {line.replace('Commandline: ', '')}\n"

        elif line.startswith("Requested-By:"):
            try:
                username = line.split()[1]
            except Exception:
                username = "unknown"
            log_entry["utilisateur_nom"] = username

        elif line.startswith("Install:"):
            message += "Installés: " + line.replace("Install: ", "") + "\n"

        elif line.startswith("End-Date:"):
            log_entry["message"] = message.strip()
            apt_logs.append(log_entry)

    return apt_logs

def send_logs_to_server():
    try:
        with open(JSON_FILE, "r", encoding="utf-8") as f:
            contenu = json.load(f)
    except Exception as e:
        print("❌ Impossible de lire le fichier JSON:", e)
        return False

    try:
        response = requests.post(URL, json=contenu, timeout=10)
        response.raise_for_status()
        print("✅ Réponse du serveur :", response.json())
        return True
    except requests.RequestException as e:
        print("❌ Erreur lors de l'envoi des logs:", e)
        return False

def main_loop():
    ip_machine = get_local_ip()
    while True:
        print(f"\n⏰ Démarrage du cycle de récupération et d'envoi des logs à {datetime.now()}")

        last_send_ts = read_last_send_timestamp()

        journald_logs, max_ts = extract_journald_logs(last_send_ts)
        apt_logs = extract_apt_logs(journald_logs)

        all_logs =  journald_logs #apt_logs  +

        # Ajout de l'IP de la machine à chaque log
        for log in all_logs:
            log["ip_machine"] = ip_machine



        if all_logs:
            with open(JSON_FILE, "w", encoding='utf-8') as f:
                json.dump(all_logs, f, indent=4, ensure_ascii=False)
            print(f"✅ {len(all_logs)} logs fusionnés sauvegardés dans '{JSON_FILE}'")
        else:
            print("ℹ️ Aucun nouveau log à sauvegarder.")

        if max_ts > last_send_ts:
            write_last_send_timestamp(max_ts)
            print(f"⏰ Dernier timestamp traité mis à jour à {max_ts}")

        # Envoi au serveur
        send_logs_to_server()

        print("⏳ Pause de 30 minutes avant le prochain cycle...")
        time.sleep(60)  # 1800 secondes = 30 minutes


if __name__ == "__main__":
    main_loop()
