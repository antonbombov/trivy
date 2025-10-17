import json
import subprocess
import shutil
from pathlib import Path
from .config import SPLOITSCAN_PATH, SPLOITSCAN_DIR, ENV, TIMEOUT
from .utils import find_existing_json

def run_sploitscan(cve_id, target_dir):
    """
    Запускает sploitscan для CVE и перемещает созданный файл в SploitScanJsons
    """
    try:
        # Создаем целевую папку SploitScanJsons
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # ПРОВЕРЯЕМ КЭШ - если файл уже существует, используем его
        existing_file = find_existing_json(cve_id, target_dir)
        if existing_file:
            return {'status': 'cached', 'file': existing_file, 'execution_time': 0}
        
        # Запускаем sploitscan - он создаст файл в sploitscan_dir
        start_time = time.time()
        result = subprocess.run(
            [sys.executable, str(SPLOITSCAN_PATH), "-e", "json", cve_id],
            capture_output=True,
            text=True,
            encoding='utf-8',
            env=ENV,
            cwd=str(SPLOITSCAN_DIR),
            timeout=TIMEOUT
        )
        execution_time = time.time() - start_time
        
        if result.returncode == 0:
            # Ищем созданный файл по шаблону *CVE-*.json
            json_files = list(SPLOITSCAN_DIR.glob(f"*{cve_id}*.json"))
            
            if json_files:
                source_file = json_files[0]
                target_file = target_dir / source_file.name
                
                # Перемещаем файл в целевую папку SploitScanJsons
                shutil.move(str(source_file), str(target_file))
                
                return {'status': 'success', 'file': target_file, 'execution_time': execution_time}
            else:
                return {'status': 'failed', 'error': 'JSON файл не создан', 'execution_time': execution_time}
        else:
            error_msg = result.stderr if result.stderr else result.stdout
            return {'status': 'failed', 'error': error_msg[:200], 'execution_time': execution_time}
            
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}

def parse_sploitscan_data(json_file):
    """
    Парсит JSON файл от sploitscan и извлекает ВСЕ данные из отчета
    """
    sploit_info = {}
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Если JSON содержит список, берем первый элемент
        if isinstance(data, list) and len(data) > 0:
            data = data[0]
        
        # ОСНОВНАЯ ИНФОРМАЦИЯ - CVE Data
        if 'CVE Data' in data:
            cve_data = data['CVE Data']
            sploit_info['cve_data'] = cve_data
        
        # EPSS DATA
        if 'EPSS Data' in data:
            epss_data = data['EPSS Data']
            sploit_info['epss'] = epss_data
        
        # CISA KEV CATALOG
        if 'CISA Data' in data:
            cisa_data = data['CISA Data']
            sploit_info['cisa_kev'] = cisa_data
        
        # EXPLOIT INFORMATION - собираем из разных источников
        exploit_info = {}
        
        # ExploitDB Data
        if 'ExploitDB Data' in data:
            exploitdb_data = data['ExploitDB Data']
            exploit_info['exploitdb'] = exploitdb_data
        
        # PacketStorm Data
        if 'PacketStorm Data' in data:
            packetstorm_data = data['PacketStorm Data']
            exploit_info['packetstorm'] = packetstorm_data
        
        # GitHub Data
        if 'GitHub Data' in data:
            github_data = data['GitHub Data']
            exploit_info['github'] = github_data
        
        # VulnCheck Data
        if 'VulnCheck Data' in data:
            vulncheck_data = data['VulnCheck Data']
            exploit_info['vulncheck'] = vulncheck_data
        
        if exploit_info:
            sploit_info['exploit'] = exploit_info
        
        # HACKERONE HACKTIVITY
        if 'HackerOne Data' in data:
            hackerone_data = data['HackerOne Data']
            sploit_info['hackerone'] = hackerone_data
        
        # PATCHING PRIORITY
        if 'Priority' in data:
            priority_data = data['Priority']
            sploit_info['priority'] = priority_data
        
        # RISK ASSESSMENT
        if 'Risk Assessment' in data:
            risk_data = data['Risk Assessment']
            sploit_info['risk'] = risk_data
        
        # NUCLEI DATA (если есть)
        if 'Nuclei Data' in data and data['Nuclei Data'] is not None:
            nuclei_data = data['Nuclei Data']
            sploit_info['nuclei'] = nuclei_data
            
    except Exception as e:
        print(f"ОШИБКА ПАРСИНГА JSON {json_file}: {e}")
    
    return sploit_info