from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from ipaddress import ip_network
from psutil import net_if_addrs
from nmap import PortScanner
from socket import AF_INET
from os import system

print(f'''
┌───────────────────────────────────────────────┐
│                                               │
│                   {Fore.MAGENTA}vulnscan{Style.RESET_ALL}                    │ 
│                    {Fore.MAGENTA}by azuk4r{Style.RESET_ALL}                  │
│                                               │
└───────────────────────────────────────────────┘
''')

# Mapa de scripts específicos por puerto
vuln_scripts = {
    21: ['ftp-vsftpd-backdoor', 'ftp-anon', 'ftp-libopie', 'ftp-proftpd-backdoor', 'ftp-vuln-cve2010-4221'],
    22: ['sshv1', 'ssh2-enum-algos'],
    23: ['telnet-encryption', 'telnet-brute'],
    25: ['smtp-vuln-cve2010-4344', 'smtp-vuln-cve2020-28017', 'smtp-open-relay'],
    53: ['dns-recursion', 'dns-zone-transfer', 'dns-nsid', 'dns-cache-snoop'],
    80: ['http-sql-injection', 'http-vuln-cve2017-5638', 'http-csrf', 'http-shellshock', 'http-vuln-cve2013-7091'],
    443: ['ssl-heartbleed', 'http-sql-injection', 'http-vuln-cve2017-5638', 'http-csrf', 'http-shellshock', 'http-vuln-cve2013-7091'],
    445: ['smb-vuln-ms17-010', 'smb-vuln-ms08-067', 'smb-enum-shares', 'smb-enum-users', 'smb-vuln-cve-2017-7494'],
    3306: ['mysql-vuln-cve2012-2122', 'mysql-empty-password', 'mysql-brute'],
    3389: ['rdp-vuln-ms12-020', 'rdp-enum-encryption'],
    161: ['snmp-brute', 'snmp-info', 'snmp-sysdescr'],
    'general': ['vulners', 'vuln']  # Añadimos ambos scripts generales aquí
}

def get_local_ip_and_subnet():
	local_ip, subnet_mask = None, None
	for iface, addrs in net_if_addrs().items():
		for addr in addrs:
			if addr.family == AF_INET and addr.address != '127.0.0.1' and not addr.address.startswith('169.254'):
				local_ip, subnet_mask = addr.address, addr.netmask
				break
		if local_ip and subnet_mask:
			break
	return local_ip, subnet_mask

def scan_vulnerabilities(ip, port):
    nm = PortScanner()
    scripts = vuln_scripts.get(port, vuln_scripts.get('general', []))  # Añadir general si no hay específico
    vuln_results = []
    
    # Ejecutar los scripts específicos y generales
    for script in scripts:
        print(f'{Fore.YELLOW}[VULN SCAN]{Style.RESET_ALL} Executing script {script} on IP {ip} Port {port}')
        vuln_scan = nm.scan(ip, str(port), arguments=f'--script {script}')
        if 'vulns' in vuln_scan:
            vuln_results.append(f'{Fore.RED}[VULNERABILITY]{Style.RESET_ALL} Vulnerability found on port {port}: {vuln_scan["vulns"]}')
        else:
            vuln_results.append(f'{Fore.GREEN}[NO VULN]{Style.RESET_ALL} No vulnerabilities found on port {port} using script {script}')
    
    return vuln_results

def nmap_syn_scan(ip, port_range):
    print(f'{Fore.CYAN}[SCAN]{Style.RESET_ALL} Running SYN scan on IP: {ip} for ports: {port_range[0]}-{port_range[1]}')
    nm = PortScanner()
    nm.scan(ip, f'{port_range[0]}-{port_range[1]}', arguments='-sS -O --min-rtt-timeout 200ms --max-rtt-timeout 1000ms --max-retries 1 --min-rate 100')
    
    for host in nm.all_hosts():
        print(f'{Fore.MAGENTA}[HOST]{Style.RESET_ALL} Host: {host} ({nm[host].hostname()})')
        print(f'{Fore.MAGENTA}[STATUS]{Style.RESET_ALL} Current state: {nm[host].state()}')
        
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            with ThreadPoolExecutor(max_workers=10) as vuln_executor:
                vuln_futures = []
                for port in lport:
                    service = nm[host][proto][port]
                    state_color = Fore.GREEN if service["state"] == "open" else (Fore.RED if service["state"] == "closed" else Fore.YELLOW)
                    print(f'{Fore.BLUE}[PORT DETECTED]{Style.RESET_ALL} Port: {Fore.YELLOW}{port}{Style.RESET_ALL} | State: {state_color}{service["state"]}{Style.RESET_ALL} | Service: {Fore.CYAN}{service["name"]}{Style.RESET_ALL}')
                    
                    # Ejecutar vulnerabilidades específicas y generales
                    vuln_futures.append(vuln_executor.submit(scan_vulnerabilities, ip, port))
                
                for future in as_completed(vuln_futures):
                    vuln_result = future.result()
                    for result in vuln_result:
                        print(result)
        
        if 'osclass' in nm[host]:
            for osclass in nm[host]['osclass']:
                print(f'{Fore.MAGENTA}[OS]{Style.RESET_ALL} OS: {osclass["osfamily"]} {osclass["osgen"]} - Accuracy: {osclass["accuracy"]}')

def ping_ip(ip):
	response = system(f'ping -n 1 -w 1000 {ip} > nul')
	return ip if response == 0 else None

def scan_active_ips(network):
    print(f'{Fore.CYAN}[NETWORK SCAN]{Style.RESET_ALL} Scanning active IPs in network: {network}')
    active_ips = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(ping_ip, network.hosts())
        for ip in results:
            if ip:
                active_ips.append(str(ip))
    return active_ips

def main():
    local_ip, subnet_mask = get_local_ip_and_subnet()
    network = ip_network(f'{local_ip}/{subnet_mask}', strict=False)
    print(f'{Fore.CYAN}[LOCAL IP]{Style.RESET_ALL} Local IP: {local_ip}')
    print(f'{Fore.CYAN}[SUBNET MASK]{Style.RESET_ALL} Subnet Mask: {subnet_mask}')
    print(f'{Fore.CYAN}[SCAN]{Style.RESET_ALL} Scanning network: {network}')
    
    active_ips = scan_active_ips(network)
    print(f'{Fore.CYAN}[ACTIVE IPS]{Style.RESET_ALL} Active IPs found: {", ".join(active_ips)}')
    
    port_range = (1, 65535)
    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.map(lambda ip: nmap_syn_scan(ip, port_range), active_ips)

if __name__ == '__main__':
    main()