# sploitscan_parser.py
import json

def parse_sploitscan_data(json_file):
    """
    Парсит JSON файл от sploitscan и извлекает ВСЕ данные из отчета
    """
    sploit_info = {}
    
    try:
        with open(json_file, 'r', encoding='utf-8-sig') as f:
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