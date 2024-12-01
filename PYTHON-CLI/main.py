import requests
import time
import nmap
from colorama import init, Fore

init(autoreset=True)

class Console:
    """Classe dédiée à la gestion de la sortie dans la console avec couleurs."""
    @staticmethod
    def print_output(text, color=Fore.WHITE):
        print(color + text)

class ScriptScanPort:
    """Classe pour le script de scan de ports IP."""
    def __init__(self, console):
        self.console = console

    def run(self, IP):
        self.console.print_output(f"root@SPARK>>>sudo spark_scanport {IP}", Fore.CYAN)
        nm = nmap.PortScanner()
        try:
            nm.scan(IP, arguments='-p- -sV')  # -p- pour scanner tous les ports, -sV pour détecter les versions de service
            if nm.all_hosts():
                for host in nm.all_hosts():
                    self.console.print_output(f"Scan de {host} :", Fore.GREEN)
                    for proto in nm[host].all_protocols():
                        self.console.print_output(f"Protocole : {proto.upper()}", Fore.YELLOW)
                        ports = nm[host][proto].keys()
                        for port in ports:
                            state = nm[host][proto][port]['state']
                            name = nm[host][proto][port].get('name', 'N/A')
                            product = nm[host][proto][port].get('product', 'N/A')
                            version = nm[host][proto][port].get('version', 'N/A')
                            result = (
                                f"Port {port}/{proto.upper()}: {state}\n"
                                f"    📝 Service : {name}\n"
                                f"    🔍 Produit : {product}\n"
                                f"    📜 Version : {version}\n"
                            )
                            self.console.print_output(result, Fore.CYAN)
            else:
                self.console.print_output("L'hôte est inactif ou inaccessible.", Fore.RED)
        except Exception as e:
            self.console.print_output(f"❌ Erreur lors de l'exécution de Nmap : {e}", Fore.RED)

class ScriptScanServer:
    """Classe pour le script de scan d'un serveur Minecraft."""
    def __init__(self, console):
        self.console = console

    def run(self, IP, Port="25565"):
        self.console.print_output(f"root@SPARK>>>mcserver {IP}:{Port}", Fore.CYAN)
        time.sleep(1)
        self.console.print_output(f"Getting Data for {IP}:{Port}", Fore.GREEN)
        time.sleep(1)

        try:
            api = requests.get(f'https://api.mcstatus.io/v2/status/java/{IP}:{Port}')
            data = api.json()

            if not data.get("online"):
                result = "🔴 Le serveur est hors ligne."
                self.console.print_output(result, Fore.RED)
            else:
                host = data.get("host", "N/A")
                ip_address = data.get("ip_address", "N/A")
                players_online = data['players'].get('online', 0)
                players_max = data['players'].get('max', "N/A")
                motd = data['motd'].get('clean', "N/A")
                version_name = data['version'].get('name_clean', "Inconnue")
                protocol = data['version'].get('protocol', "N/A")

                result = (
                    f"🟢 **Serveur en ligne**\n"
                    f"🌐 **Host** : {host}\n"
                    f"📡 **Adresse IP** : {ip_address}\n"
                    f"🔢 **Port** : {Port}\n"
                    f"👥 **Joueurs connectés** : {players_online} / {players_max}\n"
                    f"💬 **MOTD** : {motd}\n"
                    f"🔖 **Version** : {version_name}\n"
                    f"📜 **Protocole** : {protocol}"
                )
                self.console.print_output(result, Fore.GREEN)
        except Exception as e:
            result = f"❌ **Erreur** : {e}"
            self.console.print_output(result, Fore.RED)

class ScriptTest:
    """Classe pour le script de test."""
    def __init__(self, console):
        self.console = console

    def run(self, Paramètre_A, Paramètre_B):
        result = f"🧪 **Exécution de Test** avec : {Paramètre_A} et {Paramètre_B}"
        self.console.print_output(result, Fore.YELLOW)

class ApplicationCLI:
    """Application principale en ligne de commande qui gère l'exécution des scripts."""
    def __init__(self):
        self.console = Console()
        self.scripts = {
            "Minecraft Scan-Server": ScriptScanServer(self.console),
            "Scan IP (Port & Host)": ScriptScanPort(self.console),
            "Test Script": ScriptTest(self.console),
        }

    def run(self):
        """Affiche les options et permet d'exécuter les scripts."""
        while True:
            self.console.print_output("\n=== Bienvenue dans SPARK - Application CLI ===", Fore.CYAN)
            self.console.print_output("\nSélectionnez un script à exécuter :", Fore.YELLOW)

            for idx, script_name in enumerate(self.scripts.keys(), 1):
                self.console.print_output(f"{idx}. {script_name}", Fore.WHITE)

            self.console.print_output("\nEntrez le numéro du script ou 'q' pour quitter :", Fore.GREEN)
            choice = input("> ")

            if choice.lower() == 'q':
                break
            elif choice.isdigit() and 1 <= int(choice) <= len(self.scripts):
                script_name = list(self.scripts.keys())[int(choice) - 1]
                self.run_script(script_name)
            else:
                self.console.print_output("Choix invalide, essayez à nouveau.", Fore.RED)

    def run_script(self, script_name):
        """Exécute un script spécifique en fonction du nom."""
        script = self.scripts[script_name]
        self.console.print_output(f"\nExécution du script: {script_name}\n", Fore.CYAN)

        # Demander les paramètres requis pour le script
        if isinstance(script, ScriptScanServer):
            IP = input("Entrez l'IP du serveur Minecraft : ")
            Port = input("Entrez le port (par défaut 25565) : ") or "25565"
            script.run(IP, Port)
        elif isinstance(script, ScriptScanPort):
            IP = input("Entrez l'IP à scanner : ")
            script.run(IP)
        elif isinstance(script, ScriptTest):
            Paramètre_A = input("Entrez le Paramètre_A : ")
            Paramètre_B = input("Entrez le Paramètre_B : ")
            script.run(Paramètre_A, Paramètre_B)

if __name__ == "__main__":
    app = ApplicationCLI()
    app.run()
