import psutil
import time
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor

# Cache for static process info to avoid redundant calls
STATIC_CACHE = {}

def get_proc_details(proc) -> Dict[str, Any]:
    """Helper for parallel collection of single process details"""
    try:
        pid = proc.info['pid']
        name = proc.info['name']
        
        # Use cache for static fields
        if pid not in STATIC_CACHE:
            try:
                path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                path = None
                
            try:
                parent = proc.parent()
                if parent:
                    parent_pid = parent.pid
                    parent_name = parent.name()
                else:
                    parent_pid = None
                    parent_name = None
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                parent_pid = None
                parent_name = None
            
            STATIC_CACHE[pid] = {
                'path': path,
                'parent_pid': parent_pid,
                'parent_name': parent_name
            }
        
        static_info = STATIC_CACHE[pid]
        
        try:
            cpu = proc.cpu_percent(interval=None)
            memory = proc.memory_info().rss
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            cpu, memory = 0.0, 0
            
        remote_ips = []
        connection_count = 0
        try:
            # kind='inet' is safer and faster for basic network info
            connections = proc.connections(kind='inet')
            for conn in connections:
                if conn.raddr and conn.status != psutil.CONN_CLOSE_WAIT:
                    remote_ips.append(conn.raddr.ip)
            
            remote_ips = list(set(remote_ips))
            connection_count = len(connections)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
            
        return {
            'pid': pid,
            'name': name,
            'cpu': cpu,
            'memory': memory,
            'path': static_info['path'],
            'parent_pid': static_info['parent_pid'],
            'parent_name': static_info['parent_name'],
            'remote_ips': remote_ips,
            'connection_count': connection_count
        }
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None

def collect_processes() -> List[Dict[str, Any]]:
    """
    Collects live process data using psutil.
    Optimized with parallel detail fetching and caching.
    """
    current_pids = set()
    
    # Get all current processes and start CPU monitoring
    proc_objs = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
            proc_objs.append(proc)
            current_pids.add(proc.info['pid'])
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
            
    # Cleanup cache
    for pid in list(STATIC_CACHE.keys()):
        if pid not in current_pids:
            del STATIC_CACHE[pid]
            
    time.sleep(0.1)
    
    # Parallel fetch using ThreadPool
    processes_data = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(get_proc_details, proc_objs)
        for res in results:
            if res:
                processes_data.append(res)
            
    return processes_data
