import logging
import os
from pathlib import Path
from typing import Dict, Any, List

# Create logs directory if it doesn't already exist
LOG_DIR = Path(__file__).parent.parent / 'logs'
LOG_FILE = LOG_DIR / 'threats.log'

if not LOG_DIR.exists():
    os.makedirs(LOG_DIR, exist_ok=True)

# Configure logging
# Format: timestamp, threat level, PID, NAME, SCORE, IPS, PATH
logger = logging.getLogger('ProdotThreatLogger')
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('%(asctime)s %(levelname)s PID:%(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def log_threat(proc_dict: Dict[str, Any], score: int, level: str, triggered_rules: List[str]):
    """
    Logs threat information if suspicious or higher.
    Format: PID NAME SCORE IPS PATH
    """
    if level in ["SUSPICIOUS", "DANGEROUS", "CRITICAL"]:
        pid = proc_dict.get('pid', 'N/A')
        name = proc_dict.get('name', 'N/A')
        ips = ",".join(proc_dict.get('remote_ips', [])) or "None"
        path = proc_dict.get('path', 'N/A')
        
        log_msg = f"{pid} {name} SCORE:{score} IPS:{ips} PATH:{path}"
        
        # Mapping threat levels to logging levels
        if level == "CRITICAL":
            logger.critical(log_msg)
        elif level == "DANGEROUS":
            logger.error(log_msg)
        else:
            logger.warning(log_msg)
            
        # Logging triggered rules as additional info
        for rule in triggered_rules:
            logger.info(f"    - RULE_FIRED: {rule}")
