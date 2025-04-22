#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VulnOSINT Scanner v1.0
Desarrollador: Christian Duran
Escáner de Vulnerabilidades y OSINT
Herramienta para análisis de seguridad con fines educativos
"""

import argparse
import socket
import subprocess
import sys
import os
import re
import json
import requests
import whois
import dns.resolver
import nmap
import platform
import psutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Inicializar colorama
init()

class VulnOSINTScanner:
    def __init__(self):
        self.name = "VulnOSINT Scanner"
        self.version = "1.0"
        self.developer = "Christian Duran"
        self.target = None
        self.output_dir = "security_scan_results"
        self.scan_results = {}
        
    def banner(self):
        print(f"{Fore.CYAN}=" * 70)
        print(f" {self.name} v{self.version} ".center(70))
        print(f" Desarrollador: {self.developer} ".center(70))
        print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Sistema: {platform.system()} {platform.release()}")
        print("=" * 70)
        print(f"{Style.RESET_ALL}")
        
    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"{Fore.GREEN}[+] Directorio de resultados creado: {self.output_dir}{Style.RESET_ALL}")
    
    def save_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/scan_results_{timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=4)
        print(f"{Fore.GREEN}[+] Resultados guardados en: {filename}{Style.RESET_ALL}")
    
    def scan_local_system(self):
        """Analiza vulnerabilidades en el sistema local"""
        print(f"{Fore.YELLOW}[*] Iniciando escaneo del sistema local...{Style.RESET_ALL}")
        self.scan_results['local_system'] = {}
        
        # Verificar usuarios y permisos
        try:
            if platform.system() == "Windows":
                users = subprocess.check_output("net user", shell=True).decode()
                self.scan_results['local_system']['users'] = users
                
                # Verificar actualizaciones pendientes
                updates = subprocess.check_output("wmic qfe list brief", shell=True).decode()
                self.scan_results['local_system']['updates'] = updates
                
            elif platform.system() == "Linux":
                users = subprocess.check_output("cat /etc/passwd | cut -d: -f1", shell=True).decode()
                self.scan_results['local_system']['users'] = users.split()
                
                # Verificar actualizaciones pendientes
                if os.path.exists("/usr/bin/apt"):
                    updates = subprocess.check_output("apt list --upgradable", shell=True).decode()
                    self.scan_results['local_system']['updates'] = updates
            
            # Servicios en ejecución
            services = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                services.append(proc.info)
            self.scan_results['local_system']['running_services'] = services[:20]  # Limitar a 20 para brevedad
            
            # Puertos abiertos
            open_ports = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080]
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            self.scan_results['local_system']['open_ports'] = open_ports
            print(f"{Fore.GREEN}[+] Escaneo del sistema local completado{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error al escanear el sistema local: {str(e)}{Style.RESET_ALL}")
            self.scan_results['local_system']['error'] = str(e)
    
    def scan_network(self, target_ip):
        """Escanea una red o host remoto en busca de vulnerabilidades"""
        print(f"{Fore.YELLOW}[*] Iniciando escaneo de red para {target_ip}...{Style.RESET_ALL}")
        self.scan_results['network'] = {}
        
        try:
            # Inicializar el escáner nmap
            nm = nmap.PortScanner()
            
            # Escaneo básico
            print(f"{Fore.YELLOW}[*] Realizando escaneo básico de puertos...{Style.RESET_ALL}")
            nm.scan(target_ip, '21-25,80,443,3306,3389,8080', arguments='-sV')
            
            # Guardar resultados
            for host in nm.all_hosts():
                self.scan_results['network'][host] = {}
                self.scan_results['network'][host]['state'] = nm[host].state()
                
                for proto in nm[host].all_protocols():
                    self.scan_results['network'][host][proto] = {}
                    for port in nm[host][proto].keys():
                        service = nm[host][proto][port]
                        port_info = {
                            'state': service['state'],
                            'name': service['name'],
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', '')
                        }
                        self.scan_results['network'][host][proto][port] = port_info
            
            print(f"{Fore.GREEN}[+] Escaneo de red completado{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error al escanear la red: {str(e)}{Style.RESET_ALL}")
            self.scan_results['network']['error'] = str(e)
    
    def osint_domain(self, domain):
        """Realiza reconocimiento OSINT sobre un dominio"""
        print(f"{Fore.YELLOW}[*] Iniciando recolección de información OSINT para {domain}...{Style.RESET_ALL}")
        self.scan_results['osint'] = {}
        
        try:
            # WHOIS
            print(f"{Fore.YELLOW}[*] Obteniendo información WHOIS...{Style.RESET_ALL}")
            domain_whois = whois.whois(domain)
            self.scan_results['osint']['whois'] = {
                'registrar': str(domain_whois.registrar),
                'creation_date': str(domain_whois.creation_date),
                'expiration_date': str(domain_whois.expiration_date),
                'name_servers': domain_whois.name_servers
            }
            
            # DNS
            print(f"{Fore.YELLOW}[*] Resolviendo registros DNS...{Style.RESET_ALL}")
            dns_records = {}
            
            # A Records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_records['A'] = [str(rdata) for rdata in answers]
            except:
                dns_records['A'] = []
            
            # MX Records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_records['MX'] = [str(rdata) for rdata in answers]
            except:
                dns_records['MX'] = []
            
            # TXT Records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_records['TXT'] = [str(rdata) for rdata in answers]
            except:
                dns_records['TXT'] = []
            
            self.scan_results['osint']['dns'] = dns_records
            
            # HTTP Headers
            print(f"{Fore.YELLOW}[*] Analizando cabeceras HTTP...{Style.RESET_ALL}")
            try:
                response = requests.get(f'http://{domain}', timeout=5)
                self.scan_results['osint']['http_headers'] = dict(response.headers)
                
                # Comprobar tecnologías web
                self.scan_results['osint']['web_technologies'] = {}
                
                # Comprobar servidor
                server = response.headers.get('Server', '')
                self.scan_results['osint']['web_technologies']['server'] = server
                
                # Comprobar tecnologías básicas
                html_content = response.text.lower()
                technologies = []
                
                if 'wordpress' in html_content:
                    technologies.append('WordPress')
                if 'joomla' in html_content:
                    technologies.append('Joomla')
                if 'drupal' in html_content:
                    technologies.append('Drupal')
                if 'bootstrap' in html_content:
                    technologies.append('Bootstrap')
                if 'jquery' in html_content:
                    technologies.append('jQuery')
                
                self.scan_results['osint']['web_technologies']['detected'] = technologies
                
            except Exception as e:
                self.scan_results['osint']['http_headers'] = {'error': str(e)}
            
            print(f"{Fore.GREEN}[+] Recolección OSINT completada{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error en la recolección OSINT: {str(e)}{Style.RESET_ALL}")
            self.scan_results['osint']['error'] = str(e)
    
    def search_vulnerabilities(self):
        """Busca vulnerabilidades conocidas en los servicios detectados"""
        print(f"{Fore.YELLOW}[*] Buscando vulnerabilidades conocidas...{Style.RESET_ALL}")
        self.scan_results['vulnerabilities'] = []
        
        try:
            # Ejemplo: Comprobar versiones de servicios en sistemas remotos
            if 'network' in self.scan_results:
                for host in self.scan_results['network']:
                    if isinstance(self.scan_results['network'][host], dict) and 'tcp' in self.scan_results['network'][host]:
                        for port, service in self.scan_results['network'][host]['tcp'].items():
                            product = service.get('product', '').lower()
                            version = service.get('version', '')
                            
                            # Ejemplos simples de comprobaciones
                            if product == 'openssh' and version.startswith('7.') and int(version.split('.')[1]) < 7:
                                self.scan_results['vulnerabilities'].append({
                                    'host': host,
                                    'port': port,
                                    'service': product,
                                    'version': version,
                                    'vulnerability': 'OpenSSH < 7.7 tiene vulnerabilidades conocidas',
                                    'severity': 'Alta'
                                })
                            
                            if product == 'apache' and version.startswith('2.4.') and int(version.split('.')[2]) < 40:
                                self.scan_results['vulnerabilities'].append({
                                    'host': host,
                                    'port': port,
                                    'service': product,
                                    'version': version,
                                    'vulnerability': 'Apache < 2.4.40 puede tener múltiples vulnerabilidades',
                                    'severity': 'Media'
                                })
            
            # Comprobar vulnerabilidades en sistema local
            if platform.system() == "Windows":
                if not self._check_windows_defender():
                    self.scan_results['vulnerabilities'].append({
                        'host': 'local',
                        'service': 'Windows Defender',
                        'vulnerability': 'Windows Defender parece estar desactivado',
                        'severity': 'Alta'
                    })
                
                if self._check_weak_passwords():
                    self.scan_results['vulnerabilities'].append({
                        'host': 'local',
                        'service': 'Cuentas de usuario',
                        'vulnerability': 'Se detectaron posibles contraseñas débiles',
                        'severity': 'Alta'
                    })
            
            elif platform.system() == "Linux":
                if not self._check_firewall_linux():
                    self.scan_results['vulnerabilities'].append({
                        'host': 'local',
                        'service': 'Firewall',
                        'vulnerability': 'El firewall parece estar desactivado',
                        'severity': 'Media'
                    })
            
            print(f"{Fore.GREEN}[+] Búsqueda de vulnerabilidades completada{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error al buscar vulnerabilidades: {str(e)}{Style.RESET_ALL}")
    
    def _check_windows_defender(self):
        """Comprueba si Windows Defender está activado"""
        try:
            status = subprocess.check_output("powershell Get-MpComputerStatus | Select -ExpandProperty AntivirusEnabled", shell=True).decode().strip()
            return status.lower() == "true"
        except:
            return False
    
    def _check_firewall_linux(self):
        """Comprueba si el firewall está activado en Linux"""
        try:
            status = subprocess.check_output("sudo ufw status | grep -i active", shell=True).decode().strip()
            return "active" in status.lower()
        except:
            return False
    
    def _check_weak_passwords(self):
        """Comprueba contraseñas débiles (simulado)"""
        # Esto es solo simulado para fines educativos
        # En un entorno real se necesitarían privilegios administrativos
        return False
    
    def generate_report(self):
        """Genera un informe de vulnerabilidades"""
        print(f"{Fore.YELLOW}[*] Generando informe final...{Style.RESET_ALL}")
        
        report = f"""
=========================================================
        INFORME DE SEGURIDAD - {self.name} v{self.version}
        Desarrollador: {self.developer}
        Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
=========================================================

RESUMEN:
"""
        
        # Vulnerabilidades encontradas
        if 'vulnerabilities' in self.scan_results and self.scan_results['vulnerabilities']:
            report += f"\n[!] VULNERABILIDADES ENCONTRADAS: {len(self.scan_results['vulnerabilities'])}\n"
            
            for idx, vuln in enumerate(self.scan_results['vulnerabilities'], 1):
                report += f"\n{idx}. {vuln.get('vulnerability')}\n"
                report += f"   - Host: {vuln.get('host')}\n"
                report += f"   - Servicio: {vuln.get('service', 'N/A')}\n"
                report += f"   - Versión: {vuln.get('version', 'N/A')}\n"
                report += f"   - Severidad: {vuln.get('severity', 'N/A')}\n"
        else:
            report += "\n[+] No se encontraron vulnerabilidades críticas\n"
        
        # Resumen OSINT
        if 'osint' in self.scan_results:
            report += "\nINFORMACIÓN OSINT:\n"
            
            if 'whois' in self.scan_results['osint']:
                report += f"\n- Registrador: {self.scan_results['osint']['whois'].get('registrar', 'N/A')}\n"
                report += f"- Fecha de creación: {self.scan_results['osint']['whois'].get('creation_date', 'N/A')}\n"
            
            if 'dns' in self.scan_results['osint']:
                report += "\n- Registros DNS importantes:\n"
                for record_type, records in self.scan_results['osint']['dns'].items():
                    if records:
                        report += f"  * {record_type}: {', '.join(records[:3])}\n"
            
            if 'web_technologies' in self.scan_results['osint']:
                report += "\n- Tecnologías web detectadas:\n"
                server = self.scan_results['osint']['web_technologies'].get('server', 'N/A')
                report += f"  * Servidor: {server}\n"
                techs = self.scan_results['osint']['web_technologies'].get('detected', [])
                if techs:
                    report += f"  * Tecnologías: {', '.join(techs)}\n"
        
        # Puertos abiertos
        if 'network' in self.scan_results:
            report += "\nPUERTOS Y SERVICIOS DETECTADOS:\n"
            
            for host in self.scan_results['network']:
                if isinstance(self.scan_results['network'][host], dict) and 'tcp' in self.scan_results['network'][host]:
                    report += f"\n- Host: {host}\n"
                    for port, service in self.scan_results['network'][host]['tcp'].items():
                        report += f"  * Puerto {port}: {service.get('name', 'N/A')} ({service.get('product', '')} {service.get('version', '')})\n"
        
        # Sistema local
        if 'local_system' in self.scan_results:
            report += "\nINFORMACIÓN DEL SISTEMA LOCAL:\n"
            
            if 'open_ports' in self.scan_results['local_system']:
                report += f"\n- Puertos abiertos: {', '.join(map(str, self.scan_results['local_system']['open_ports']))}\n"
        
        # Recomendaciones
        report += """
RECOMENDACIONES GENERALES:
1. Actualizar todos los servicios a sus últimas versiones
2. Cambiar contraseñas débiles
3. Activar y configurar firewalls
4. Implementar políticas de seguridad
5. Realizar auditorías de seguridad periódicas
"""
        
        # Guardar informe
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{self.output_dir}/security_report_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[+] Informe guardado en: {report_file}{Style.RESET_ALL}")
        return report_file
    
    def run(self, args):
        """Ejecuta el escaneo completo basado en los argumentos proporcionados"""
        self.banner()
        self.create_output_dir()
        
        if args.local:
            self.scan_local_system()
        
        if args.target:
            self.target = args.target
            # Determinar si es IP o dominio
            if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', args.target):
                self.scan_network(args.target)
            else:
                self.osint_domain(args.target)
                # También escanear la IP asociada
                try:
                    ip = socket.gethostbyname(args.target)
                    self.scan_network(ip)
                except:
                    print(f"{Fore.RED}[!] No se pudo resolver el dominio a IP{Style.RESET_ALL}")
        
        self.search_vulnerabilities()
        self.save_results()
        report_file = self.generate_report()
        
        print(f"\n{Fore.GREEN}[+] Escaneo completado. Revisa el informe para más detalles: {report_file}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description=f'VulnOSINT Scanner v1.0 - Desarrollador: Christian Duran')
    parser.add_argument('-t', '--target', help='IP o dominio objetivo')
    parser.add_argument('-l', '--local', action='store_true', help='Escanear sistema local')
    parser.add_argument('--osint', action='store_true', help='Realizar solo análisis OSINT (requiere dominio)')
    parser.add_argument('--vuln', action='store_true', help='Realizar solo análisis de vulnerabilidades')
    
    args = parser.parse_args()
    
    if not (args.target or args.local):
        parser.print_help()
        sys.exit(1)
    
    try:
        scanner = VulnOSINTScanner()
        scanner.run(args)
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[*] Escaneo interrumpido por el usuario{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}\n[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
