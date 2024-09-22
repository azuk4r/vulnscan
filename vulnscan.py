from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from vuln_scripts import vuln_scripts
from ipaddress import ip_network
from psutil import net_if_addrs
from nmap import PortScanner
from socket import AF_INET
from os import system

init(autoreset=True)
print(f'''
┌───────────────────────────────────────────────┐
│                                               │
│                   {Fore.MAGENTA}vulnscan{Style.RESET_ALL}                    │ 
│                    {Fore.MAGENTA}by azuk4r{Style.RESET_ALL}                  │
│                                               │
└───────────────────────────────────────────────┘
''')

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

def scan_vulnerabilities(ip, port, script):
	nm = PortScanner()
	try:
		vuln_scan = nm.scan(ip, str(port), arguments=f'--script {script}')
		script_output = vuln_scan.get('scan', {}).get(ip, {}).get('tcp', {}).get(port, {}).get('script', {}).get(script, '')
		if script_output:
			vuln_message = f'{Fore.RED}[VULNERABILITY]{Style.RESET_ALL} Vulnerability found on port {port} using script {script}:\n{script_output}'
			return vuln_message
		else:
			no_vuln_message = f'{Fore.GREEN}[NO VULN]{Style.RESET_ALL} No vulnerabilities found on port {port} using script {script}'
			return no_vuln_message
	except Exception as e:
		error_message = f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error executing script {script} on port {port}: {e}'
		return error_message

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
					service_name = service["name"] if service["name"] else "unknown"
					print(f'{Fore.BLUE}[PORT DETECTED]{Style.RESET_ALL} Port: {Fore.YELLOW}{port}{Style.RESET_ALL} | State: {state_color}{service["state"]}{Style.RESET_ALL} | Service: {Fore.CYAN}{service_name}{Style.RESET_ALL}')
					general_scripts = vuln_scripts.get('general', [])
					port_scripts = vuln_scripts.get(port, [])
					for script in general_scripts:
						vuln_futures.append(vuln_executor.submit(scan_vulnerabilities, ip, port, script))
					for script in port_scripts:
						vuln_futures.append(vuln_executor.submit(scan_vulnerabilities, ip, port, script))
				for future in as_completed(vuln_futures):
					vuln_result = future.result()
					print(vuln_result)
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
	if not local_ip or not subnet_mask:
		print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Unable to determine local IP and subnet mask.')
		return
	network = ip_network(f'{local_ip}/{subnet_mask}', strict=False)
	print(f'{Fore.CYAN}[LOCAL IP]{Style.RESET_ALL} Local IP: {local_ip}')
	print(f'{Fore.CYAN}[SUBNET MASK]{Style.RESET_ALL} Subnet Mask: {subnet_mask}')
	print(f'{Fore.CYAN}[SCAN]{Style.RESET_ALL} Scanning network: {network}')
	active_ips = scan_active_ips(network)
	if not active_ips:
		print(f'{Fore.YELLOW}[INFO]{Style.RESET_ALL} No active IPs found in the network.')
		return
	print(f'{Fore.CYAN}[ACTIVE IPS]{Style.RESET_ALL} Active IPs found: {", ".join(active_ips)}')
	port_range = (1, 65535)
	with ThreadPoolExecutor(max_workers=3) as executor:
		executor.map(lambda ip: nmap_syn_scan(ip, port_range), active_ips)

if __name__ == '__main__':
	main()