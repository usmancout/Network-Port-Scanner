# scanner/firewall_simulator.py
import re
from datetime import datetime

class FirewallSimulator:
    def __init__(self):
        self.rules = []
        self.rule_id_counter = 1
        self.traffic_log = []
        
    def add_rule(self, action, ip, port, protocol, priority=100):
        """Add a new firewall rule"""
        rule = {
            'id': self.rule_id_counter,
            'action': action,  # 'allow' or 'deny'
            'ip': ip,
            'port': port,
            'protocol': protocol.upper(),
            'priority': priority,
            'created_at': datetime.now().isoformat()
        }
        self.rules.append(rule)
        self.rule_id_counter += 1
        
        # Sort rules by priority (lower number = higher priority)
        self.rules.sort(key=lambda x: x['priority'])
        
        return rule
    
    def delete_rule(self, rule_id):
        """Delete a firewall rule by ID"""
        self.rules = [r for r in self.rules if r['id'] != rule_id]
        return True
    
    def get_rules(self):
        """Get all firewall rules"""
        return self.rules
    
    def test_traffic(self, ip, port, protocol):
        """Test if traffic would be allowed or blocked"""
        port = int(port) if port else None
        protocol = protocol.upper() if protocol else None
        
        matched_rule = None
        
        # Check rules in priority order
        for rule in self.rules:
            if self._match_rule(rule, ip, port, protocol):
                matched_rule = rule
                break
        
        result = {
            'ip': ip,
            'port': port,
            'protocol': protocol,
            'action': matched_rule['action'] if matched_rule else 'allow',
            'matched_rule': matched_rule,
            'timestamp': datetime.now().isoformat(),
            'default_policy': not matched_rule
        }
        
        self.traffic_log.append(result)
        
        return result
    
    def _match_rule(self, rule, ip, port, protocol):
        """Check if traffic matches a rule"""
        # Match IP
        if rule['ip'] != '*' and rule['ip'] != ip:
            if not self._match_ip_range(rule['ip'], ip):
                return False
        
        # Match Port
        if rule['port'] != '*':
            if str(rule['port']) != str(port):
                if not self._match_port_range(rule['port'], port):
                    return False
        
        # Match Protocol
        if rule['protocol'] != '*' and rule['protocol'] != protocol:
            return False
        
        return True
    
    def _match_ip_range(self, rule_ip, test_ip):
        """Match IP address or CIDR range"""
        if '/' in rule_ip:
            # CIDR notation
            try:
                from ipaddress import ip_network, ip_address
                network = ip_network(rule_ip, strict=False)
                return ip_address(test_ip) in network
            except:
                return False
        elif '-' in rule_ip:
            # Range notation (e.g., 192.168.1.1-192.168.1.50)
            try:
                start_ip, end_ip = rule_ip.split('-')
                from ipaddress import ip_address
                return ip_address(start_ip) <= ip_address(test_ip) <= ip_address(end_ip)
            except:
                return False
        else:
            return rule_ip == test_ip
    
    def _match_port_range(self, rule_port, test_port):
        """Match port range"""
        if '-' in str(rule_port):
            try:
                start_port, end_port = map(int, str(rule_port).split('-'))
                return start_port <= int(test_port) <= end_port
            except:
                return False
        return False
    
    def get_traffic_log(self):
        """Get traffic log"""
        return self.traffic_log
    
    def clear_traffic_log(self):
        """Clear traffic log"""
        self.traffic_log = []
        return True
    
    def get_statistics(self):
        """Get firewall statistics"""
        total = len(self.traffic_log)
        if total == 0:
            return {
                'total': 0,
                'allowed': 0,
                'blocked': 0,
                'allow_percentage': 0,
                'block_percentage': 0
            }
        
        allowed = sum(1 for log in self.traffic_log if log['action'] == 'allow')
        blocked = total - allowed
        
        return {
            'total': total,
            'allowed': allowed,
            'blocked': blocked,
            'allow_percentage': round((allowed / total) * 100, 2),
            'block_percentage': round((blocked / total) * 100, 2)
        }