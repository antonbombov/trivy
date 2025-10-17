import os
import json
from pathlib import Path
from datetime import datetime

def find_existing_json(cve_id, target_dir):
    """
    Ищет существующий JSON файл для CVE в кэше
    """
    json_files = list(target_dir.glob(f"*{cve_id}*.json"))
    return json_files[0] if json_files else None

def calculate_optimal_workers(total_cves):
    """
    Рассчитывает оптимальное количество workers
    """
    cpu_count = os.cpu_count() or 4
    
    if total_cves <= 10:
        workers = min(3, cpu_count)
    elif total_cves <= 30:
        workers = min(5, cpu_count)
    else:
        workers = min(7, cpu_count)
    
    return workers

def save_enriched_report(trivy_data, output_path):
    """
    Сохраняет обогащенный отчет
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(trivy_data, f, indent=2, ensure_ascii=False)

def get_timestamp():
    """
    Возвращает текущую временную метку
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")