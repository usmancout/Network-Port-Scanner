# scanner/port_scanner.py
import socket
import nmap
from scapy.all import *
from datetime import datetime
import concurrent.futures

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        
    def scan(self, target, scan_type, port_range):
        """Main scan method that delegates to specific scan types"""
        results = []

        resolved = self.resolve_target(target)

        try:
            if scan_type == 'TCP SYN':
                results = self.tcp_syn_scan(resolved, port_range)
            elif scan_type == 'UDP':
                results = self.udp_scan(resolved, port_range)
            elif scan_type == 'Full Connect':
                results = self.full_connect_scan(resolved, port_range)
            elif scan_type == 'Quick Scan':
                results = self.quick_scan(resolved)
            else:
                results = self.tcp_syn_scan(resolved, port_range)
        except Exception as e:
            results = [{'error': str(e), 'target': target}]
            
        return results
    
    def tcp_syn_scan(self, target, port_range):
        """TCP SYN scan using nmap"""
        results = []
        try:
            self.nm.scan(target, port_range, arguments='-sS -T4')
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        results.append({
                            'ip': host,
                            'port': port,
                            'protocol': proto.upper(),
                            'state': service['state'],
                            'service': service.get('name', 'unknown'),
                            'version': service.get('version', ''),
                            'product': service.get('product', ''),
                            'scan_type': 'TCP SYN'
                        })
        except Exception as e:
            # Fallback to simple TCP connect scan if SYN scan fails (requires root)
            results = self.full_connect_scan(target, port_range)
            
        return results
    
    def full_connect_scan(self, target, port_range):
        """Full TCP connect scan"""
        results = []
        start_port, end_port = map(int, port_range.split('-'))
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    
                    return {
                        'ip': target,
                        'port': port,
                        'protocol': 'TCP',
                        'state': 'open',
                        'service': service,
                        'version': '',
                        'product': '',
                        'scan_type': 'Full Connect'
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in range(start_port, end_port + 1)]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        return results
    
    def udp_scan(self, target, port_range):
        """UDP scan using nmap"""
        results = []
        try:
            self.nm.scan(target, port_range, arguments='-sU -T4')
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    if proto == 'udp':
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            service = self.nm[host][proto][port]
                            results.append({
                                'ip': host,
                                'port': port,
                                'protocol': 'UDP',
                                'state': service['state'],
                                'service': service.get('name', 'unknown'),
                                'version': service.get('version', ''),
                                'product': service.get('product', ''),
                                'scan_type': 'UDP'
                            })
        except Exception as e:
            results = [{'error': f'UDP scan failed: {str(e)}', 'target': target}]
            
        return results
    
    def quick_scan(self, target):
        """Quick scan of common ports"""
        common_ports = '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443'
        return self.full_connect_scan(target, common_ports.replace(',', '-'))
    
    def get_service_info(self, port):
        """Get service information for a port"""
        try:
            return socket.getservbyport(port)
        except:
            return 'unknown'

    def resolve_target(self, target):

        try:
            return socket.gethostbyname(target)
        except:
            return target   # if already IP
