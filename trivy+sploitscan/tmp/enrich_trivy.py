import json
import os
import subprocess
import sys
import time
import concurrent.futures
from pathlib import Path
from datetime import datetime
import shutil

def find_existing_json(cve_id, target_dir):
    """
    Ищет существующий JSON файл для CVE в кэше
    """
    json_files = list(target_dir.glob(f"*{cve_id}*.json"))
    if json_files:
        return json_files[0]
    return None

def run_sploitscan(cve_id, target_dir):
    """
    Запускает sploitscan для CVE и перемещает созданный файл в SploitScanJsons
    """
    try:
        current_script_dir = Path(__file__).parent
        sploitscan_dir = current_script_dir.parent
        sploitscan_path = sploitscan_dir / "sploitscan.py"
        
        # Создаем целевую папку SploitScanJsons
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # ПРОВЕРЯЕМ КЭШ - если файл уже существует, используем его
        existing_file = find_existing_json(cve_id, target_dir)
        if existing_file:
            return {'status': 'cached', 'file': existing_file, 'execution_time': 0}
        
        # Устанавливаем правильную кодировку для Windows
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        
        # Запускаем sploitscan - он создаст файл в sploitscan_dir
        start_time = time.time()
        result = subprocess.run(
            [sys.executable, str(sploitscan_path), "-e", "json", cve_id],
            capture_output=True,
            text=True,
            encoding='utf-8',
            env=env,
            cwd=str(sploitscan_dir),
            timeout=60
        )
        execution_time = time.time() - start_time
        
        if result.returncode == 0:
            # Ищем созданный файл по шаблону *CVE-*.json
            json_files = list(sploitscan_dir.glob(f"*{cve_id}*.json"))
            
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

def process_single_cve(args):
    """
    Обрабатывает одну CVE (для параллельной обработки)
    """
    cve_id, target_dir, attempt = args
    result = run_sploitscan(cve_id, target_dir)
    
    if result['status'] == 'success':
        sploit_info = parse_sploitscan_data(result['file'])
        return cve_id, {'status': 'success', 'data': sploit_info, 'execution_time': result['execution_time'], 'attempt': attempt}
    elif result['status'] == 'cached':
        sploit_info = parse_sploitscan_data(result['file'])
        return cve_id, {'status': 'cached', 'data': sploit_info, 'execution_time': result['execution_time'], 'attempt': attempt}
    else:
        return cve_id, {'status': 'failed', 'error': result['error'], 'execution_time': result['execution_time'], 'attempt': attempt}

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

def enrich_trivy_report(trivy_report_path, max_workers=None):
    """
    Обогащает отчет Trivy с параллельной обработкой и кэшированием
    """
    try:
        with open(trivy_report_path, 'r', encoding='utf-8') as f:
            trivy_data = json.load(f)
        
        print(f"Обработка отчета: {trivy_report_path}")
        
        # Собираем CVE
        cve_list = set()
        
        if 'Results' in trivy_data:
            for result in trivy_data['Results']:
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        if 'VulnerabilityID' in vuln:
                            cve_id = vuln['VulnerabilityID']
                            if cve_id.startswith('CVE-'):
                                cve_list.add(cve_id)
        
        cve_list = sorted(list(cve_list))
        total_cves = len(cve_list)
        
        target_dir = Path(__file__).parent / "SploitScanJsons"
        
        # АВТОМАТИЧЕСКИЙ РАСЧЕТ WORKERS
        if max_workers is None:
            max_workers = calculate_optimal_workers(total_cves)
        
        # ПРОВЕРЯЕМ КЭШ ПЕРЕД ОБРАБОТКОЙ
        cached_cves = []
        uncached_cves = []
        
        for cve_id in cve_list:
            if find_existing_json(cve_id, target_dir):
                cached_cves.append(cve_id)
            else:
                uncached_cves.append(cve_id)
        
        print(f"Найдено {total_cves} CVE")
        print(f"  [CACHE] В кэше: {len(cached_cves)} CVE")
        print(f"  [SCAN]  Требуют сканирования: {len(uncached_cves)} CVE")
        print(f"Файлы sploitscan сохраняются в: {target_dir}")
        print(f"Параллельных workers: {max_workers}")
        print(f"Процессоров в системе: {os.cpu_count()}")
        print("=" * 60)
        
        # ПАРАЛЛЕЛЬНАЯ ОБРАБОТКА С КЭШИРОВАНИЕМ
        sploitscan_results = {}
        failed_cves = set()
        stats = {'cached': len(cached_cves), 'success': 0, 'failed': 0, 'retry_success': 0}
        
        # Сначала добавляем закэшированные CVE
        for cve_id in cached_cves:
            json_file = find_existing_json(cve_id, target_dir)
            sploit_info = parse_sploitscan_data(json_file)
            sploitscan_results[cve_id] = sploit_info
            print(f"[CACHE] {cve_id} УСПЕХ (из кэша)")
        
        # Обрабатываем только те CVE, которых нет в кэше
        if uncached_cves:
            # Первая попытка
            print(f"\n[SCAN] Сканирование {len(uncached_cves)} CVE...")
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                tasks = [(cve_id, target_dir, 1) for cve_id in uncached_cves]
                future_to_cve = {executor.submit(process_single_cve, task): task for task in tasks}
                
                completed = 0
                for future in concurrent.futures.as_completed(future_to_cve):
                    cve_id, result = future.result()
                    completed += 1
                    
                    if result['status'] == 'success':
                        sploitscan_results[cve_id] = result['data']
                        stats['success'] += 1
                        print(f"[{completed}/{len(uncached_cves)}] {cve_id} УСПЕХ ({result['execution_time']:.1f}с)")
                    elif result['status'] == 'cached':
                        sploitscan_results[cve_id] = result['data']
                        stats['cached'] += 1
                        print(f"[{completed}/{len(uncached_cves)}] {cve_id} УСПЕХ КЭШ ({result['execution_time']:.1f}с)")
                    else:
                        failed_cves.add(cve_id)
                        stats['failed'] += 1
                        print(f"[{completed}/{len(uncached_cves)}] {cve_id} ОШИБКА ({result['execution_time']:.1f}с)")
            
            # Вторая попытка для неудавшихся CVE
            if failed_cves:
                print(f"\n[RETRY] Повторная попытка для {len(failed_cves)} CVE...")
                retry_cves = list(failed_cves)
                
                with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                    tasks = [(cve_id, target_dir, 2) for cve_id in retry_cves]
                    future_to_cve = {executor.submit(process_single_cve, task): task for task in tasks}
                    
                    completed_retry = 0
                    for future in concurrent.futures.as_completed(future_to_cve):
                        cve_id, result = future.result()
                        completed_retry += 1
                        
                        if result['status'] == 'success':
                            sploitscan_results[cve_id] = result['data']
                            failed_cves.remove(cve_id)
                            stats['retry_success'] += 1
                            print(f"[{completed_retry}/{len(retry_cves)}] {cve_id} УСПЕХ ПОВТОР ({result['execution_time']:.1f}с)")
                        else:
                            print(f"[{completed_retry}/{len(retry_cves)}] {cve_id} ОШИБКА ПОВТОР ({result['execution_time']:.1f}с)")
        
        print("=" * 60)
        print("СТАТИСТИКА ОБРАБОТКИ:")
        print(f"  Из кэша:               {stats['cached']}")
        print(f"  Успешно с первой попытки: {stats['success']}")
        print(f"  Успешно после повтора:    {stats['retry_success']}")
        print(f"  Всего успешно:           {stats['cached'] + stats['success'] + stats['retry_success']}/{total_cves}")
        print(f"  Осталось ошибок:         {len(failed_cves)}")
        
        # Добавляем значения по умолчанию для оставшихся ошибок
        for cve_id in failed_cves:
            sploitscan_results[cve_id] = {
                "error": "Не удалось получить данные после 2 попыток"
            }
        
        # Обогащаем отчет
        enriched_count = 0
        if 'Results' in trivy_data:
            for result in trivy_data['Results']:
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        cve_id = vuln.get('VulnerabilityID')
                        if cve_id in sploitscan_results:
                            vuln['sploitscan'] = sploitscan_results[cve_id]
                            enriched_count += 1
        
        # Сохраняем обогащенный отчет
        output_path = trivy_report_path.parent / f"{trivy_report_path.stem}_enriched.json"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(trivy_data, f, indent=2, ensure_ascii=False)
        
        # Показываем созданные файлы
        json_files = list(target_dir.glob("*.json"))
        print(f"ФАЙЛОВ В КЭШЕ: {len(json_files)}")
        print(f"ОБОГАЩЕНО УЯЗВИМОСТЕЙ: {enriched_count}")
        print(f"РЕЗУЛЬТАТ: {output_path.name}")
        
        return output_path
        
    except Exception as e:
        print(f"ОШИБКА: {e}")
        return None

def main():
    script_dir = Path(__file__).parent
    
    print("=" * 60)
    print("ОБОГАЩЕНИЕ TRIVY SPLOITSCAN")
    print("ПОЛНАЯ ИНФОРМАЦИЯ ОБ ЭКСПЛОЙТАХ")
    print("=" * 60)
    
    trivy_files = list(script_dir.glob("*.json"))
    trivy_files = [f for f in trivy_files if not f.name.endswith('_enriched.json')]
    
    if not trivy_files:
        print("Нет отчетов Trivy")
        return
    
    for trivy_file in trivy_files:
        print(f"\nОБРАБОТКА: {trivy_file.name}")
        print("=" * 40)
        
        start_time = time.time()
        enriched_file = enrich_trivy_report(trivy_file)
        total_time = time.time() - start_time
        
        if enriched_file:
            print(f"УСПЕШНО ЗА {total_time:.1f}с")
        else:
            print(f"ОШИБКА")

if __name__ == "__main__":
    main()