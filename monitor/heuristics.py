import json
import os
from pathlib import Path
from typing import Tuple, List, Dict, Any

# Load whitelist once at import time
WHITELIST_PATH = Path(__file__).parent.parent / 'config' / 'whitelist.json'
WHITELIST = set()

if WHITELIST_PATH.exists():
    try:
        with open(WHITELIST_PATH, 'r') as f:
            data = json.load(f)
            WHITELIST = {name.lower() for name in data}
    except Exception:
        pass

def get_threat_level(score: int) -> str:
    if 0 <= score <= 20:
        return "SAFE"
    elif 21 <= score <= 50:
        return "SUSPICIOUS"
    elif 51 <= score <= 80:
        return "DANGEROUS"
    else:
        return "CRITICAL"

def score_process(proc_dict: Dict[str, Any]) -> Tuple[int, str, List[str]]:
    """
    Threat scoring engine.
    Returns (score, level, triggered_rules).
    """
    name = proc_dict.get('name', '').lower()
    
    # Rule 0: Whitelist check
    if name in WHITELIST:
        return 0, "SAFE", []
        
    score = 0
    triggered_rules = []
    
    # CPU usage rule
    cpu = proc_dict.get('cpu', 0)
    if cpu > 70:
        score += 20
        triggered_rules.append(f"High CPU usage ({cpu}%): +20")
        
    # Memory usage rule (500MB = 524288000 bytes)
    memory = proc_dict.get('memory', 0)
    if memory > 524288000:
        score += 15
        triggered_rules.append(f"High memory usage ({memory / 1024 / 1024:.1f}MB): +15")
        
    # Path location rule
    path = proc_dict.get('path')
    if path:
        path_str = str(path)
        suspicious_paths = ['/tmp', '/var/tmp', 'AppData', 'Temp', '.cache']
        for sp in suspicious_paths:
            if sp in path_str:
                score += 35
                triggered_rules.append(f"Execution from suspicious path ({sp}): +35")
                break
                
    # Remote IPs/Network rule
    remote_ips = proc_dict.get('remote_ips', [])
    if remote_ips:
        non_local_ips = []
        for ip in remote_ips:
            if not (ip.startswith('127.') or 
                    ip.startswith('192.168.') or 
                    ip.startswith('10.') or 
                    ip.startswith('169.254.')):
                non_local_ips.append(ip)
        
        if non_local_ips:
            score += 25
            triggered_rules.append(f"Persistence of remote external connections: +25")
            
    # Connection count rule
    conn_count = proc_dict.get('connection_count', 0)
    if conn_count > 10:
        score += 20
        triggered_rules.append(f"High network connection count ({conn_count}): +20")
        
    # Name rule (no vowels, length > 4)
    vowels = 'aeiou'
    has_vowels = any(char in vowels for char in name)
    if not has_vowels and len(name) > 4:
        score += 15
        triggered_rules.append(f"Suspicious process name (no vowels): +15")
        
    # Parent/Child relationship rule
    parent_name = (proc_dict.get('parent_name') or '').lower()
    is_browser_or_editor = any(x in name for x in ['chrome', 'firefox', 'msedge', 'code', 'sublime', 'vim', 'nano', 'python'])
    suspicious_parents = ['explorer.exe', 'bash', 'zsh', 'powershell']
    
    if parent_name in suspicious_parents and not is_browser_or_editor:
        score += 20
        triggered_rules.append(f"Suspicious parent ({parent_name}): +20")
        
    level = get_threat_level(score)
    return score, level, triggered_rules
