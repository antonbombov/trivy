import json
from pathlib import Path

def extract_cves_from_report(trivy_report_path):
    """
    Извлекает все CVE из отчета Trivy
    """
    cve_list = set()
    
    try:
        with open(trivy_report_path, 'r', encoding='utf-8') as f:
            trivy_data = json.load(f)
        
        if 'Results' in trivy_data:
            for result in trivy_data['Results']:
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        if 'VulnerabilityID' in vuln:
                            cve_id = vuln['VulnerabilityID']
                            if cve_id.startswith('CVE-'):
                                cve_list.add(cve_id)
        
        return sorted(list(cve_list)), trivy_data
        
    except Exception as e:
        print(f"ОШИБКА ЧТЕНИЯ ОТЧЕТА: {e}")
        return [], None

def enrich_report_with_sploitscan(trivy_data, sploitscan_results):
    """
    Обогащает отчет Trivy данными из SploitScan
    """
    enriched_count = 0
    
    if 'Results' in trivy_data:
        for result in trivy_data['Results']:
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    cve_id = vuln.get('VulnerabilityID')
                    if cve_id in sploitscan_results:
                        vuln['sploitscan'] = sploitscan_results[cve_id]
                        enriched_count += 1
    
    return enriched_count

def check_cached_cves(cve_list, target_dir):
    """
    Проверяет какие CVE уже есть в кэше
    """
    cached_cves = []
    uncached_cves = []
    
    for cve_id in cve_list:
        json_files = list(target_dir.glob(f"*{cve_id}*.json"))
        if json_files:
            cached_cves.append(cve_id)
        else:
            uncached_cves.append(cve_id)
    
    return cached_cves, uncached_cves

def load_cached_results(cached_cves, target_dir):
    """
    Загружает результаты из кэша
    """
    from .sploitscan_client import parse_sploitscan_data
    
    sploitscan_results = {}
    for cve_id in cached_cves:
        json_file = list(target_dir.glob(f"*{cve_id}*.json"))[0]
        sploit_info = parse_sploitscan_data(json_file)
        sploitscan_results[cve_id] = sploit_info
    
    return sploitscan_results