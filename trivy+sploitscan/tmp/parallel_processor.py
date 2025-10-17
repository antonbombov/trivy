import time
import concurrent.futures
from .sploitscan_client import run_sploitscan, parse_sploitscan_data
from .config import MAX_RETRIES

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

def process_cves_parallel(cve_list, target_dir, max_workers, stats_callback=None):
    """
    Параллельно обрабатывает список CVE с повторными попытками
    """
    sploitscan_results = {}
    failed_cves = set()
    stats = {'cached': 0, 'success': 0, 'failed': 0, 'retry_success': 0}
    
    # Первая попытка
    print(f"[SCAN] Сканирование {len(cve_list)} CVE...")
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        tasks = [(cve_id, target_dir, 1) for cve_id in cve_list]
        future_to_cve = {executor.submit(process_single_cve, task): task for task in tasks}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_cve):
            cve_id, result = future.result()
            completed += 1
            
            if result['status'] == 'success':
                sploitscan_results[cve_id] = result['data']
                stats['success'] += 1
                if stats_callback:
                    stats_callback(completed, len(cve_list), cve_id, f"УСПЕХ ({result['execution_time']:.1f}с)")
            elif result['status'] == 'cached':
                sploitscan_results[cve_id] = result['data']
                stats['cached'] += 1
                if stats_callback:
                    stats_callback(completed, len(cve_list), cve_id, f"УСПЕХ КЭШ ({result['execution_time']:.1f}с)")
            else:
                failed_cves.add(cve_id)
                stats['failed'] += 1
                if stats_callback:
                    stats_callback(completed, len(cve_list), cve_id, f"ОШИБКА ({result['execution_time']:.1f}с)")
    
    # Повторные попытки для неудавшихся CVE
    for retry_attempt in range(2, MAX_RETRIES + 1):
        if not failed_cves:
            break
            
        print(f"\n[RETRY] Повторная попытка #{retry_attempt-1} для {len(failed_cves)} CVE...")
        retry_cves = list(failed_cves)
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            tasks = [(cve_id, target_dir, retry_attempt) for cve_id in retry_cves]
            future_to_cve = {executor.submit(process_single_cve, task): task for task in tasks}
            
            completed_retry = 0
            for future in concurrent.futures.as_completed(future_to_cve):
                cve_id, result = future.result()
                completed_retry += 1
                
                if result['status'] == 'success':
                    sploitscan_results[cve_id] = result['data']
                    failed_cves.remove(cve_id)
                    stats['retry_success'] += 1
                    if stats_callback:
                        stats_callback(completed_retry, len(retry_cves), cve_id, f"УСПЕХ ПОВТОР ({result['execution_time']:.1f}с)")
                else:
                    if stats_callback:
                        stats_callback(completed_retry, len(retry_cves), cve_id, f"ОШИБКА ПОВТОР ({result['execution_time']:.1f}с)")
    
    return sploitscan_results, failed_cves, stats