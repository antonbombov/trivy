import time
import sys
import os

# Добавляем текущую директорию в путь для импорта модулей
sys.path.append(os.path.dirname(__file__))

from utils import calculate_optimal_workers, save_enriched_report, get_timestamp
from report_enricher import extract_cves_from_report, enrich_report_with_sploitscan, check_cached_cves, load_cached_results
from parallel_processor import process_cves_parallel
from config import TARGET_DIR, MAX_WORKERS_AUTO, DEFAULT_WORKERS

def print_progress(completed, total, cve_id, status):
    """
    Callback для вывода прогресса обработки
    """
    print(f"[{completed}/{total}] {cve_id} {status}")

def print_stats(stats, total_cves, failed_cves):
    """
    Выводит статистику обработки
    """
    print("=" * 60)
    print("СТАТИСТИКА ОБРАБОТКИ:")
    print(f"  Из кэша:               {stats['cached']}")
    print(f"  Успешно с первой попытки: {stats['success']}")
    print(f"  Успешно после повтора:    {stats['retry_success']}")
    print(f"  Всего успешно:           {stats['cached'] + stats['success'] + stats['retry_success']}/{total_cves}")
    print(f"  Осталось ошибок:         {len(failed_cves)}")

def enrich_trivy_report(trivy_report_path, max_workers=None):
    """
    Обогащает отчет Trivy с параллельной обработкой и кэшированием
    """
    try:
        print(f"Обработка отчета: {trivy_report_path}")
        
        # Извлекаем CVE из отчета
        cve_list, trivy_data = extract_cves_from_report(trivy_report_path)
        if not cve_list:
            print("В отчете не найдено CVE для обработки")
            return None
        
        total_cves = len(cve_list)
        
        # Определяем количество workers
        if max_workers is None:
            if MAX_WORKERS_AUTO:
                max_workers = calculate_optimal_workers(total_cves)
            else:
                max_workers = DEFAULT_WORKERS
        
        # Проверяем кэш
        cached_cves, uncached_cves = check_cached_cves(cve_list, TARGET_DIR)
        
        print(f"Найдено {total_cves} CVE")
        print(f"  [CACHE] В кэше: {len(cached_cves)} CVE")
        print(f"  [SCAN]  Требуют сканирования: {len(uncached_cves)} CVE")
        print(f"Файлы sploitscan сохраняются в: {TARGET_DIR}")
        print(f"Параллельных workers: {max_workers}")
        print(f"Процессоров в системе: {os.cpu_count()}")
        print("=" * 60)
        
        # Загружаем закэшированные результаты
        sploitscan_results = load_cached_results(cached_cves, TARGET_DIR)
        for cve_id in cached_cves:
            print(f"[CACHE] {cve_id} УСПЕХ (из кэша)")
        
        # Обрабатываем CVE которых нет в кэше
        if uncached_cves:
            new_results, failed_cves, stats = process_cves_parallel(
                uncached_cves, TARGET_DIR, max_workers, print_progress
            )
            sploitscan_results.update(new_results)
            stats['cached'] = len(cached_cves)
        else:
            failed_cves = set()
            stats = {'cached': len(cached_cves), 'success': 0, 'failed': 0, 'retry_success': 0}
        
        # Выводим статистику
        print_stats(stats, total_cves, failed_cves)
        
        # Добавляем ошибки для неудавшихся CVE
        for cve_id in failed_cves:
            sploitscan_results[cve_id] = {"error": "Не удалось получить данные"}
        
        # Обогащаем отчет
        enriched_count = enrich_report_with_sploitscan(trivy_data, sploitscan_results)
        
        # Сохраняем результат
        output_path = trivy_report_path.parent / f"{trivy_report_path.stem}_enriched.json"
        save_enriched_report(trivy_data, output_path)
        
        # Показываем итоги
        json_files = list(TARGET_DIR.glob("*.json"))
        print(f"ФАЙЛОВ В КЭШЕ: {len(json_files)}")
        print(f"ОБОГАЩЕНО УЯЗВИМОСТЕЙ: {enriched_count}")
        print(f"РЕЗУЛЬТАТ: {output_path.name}")
        
        return output_path
        
    except Exception as e:
        print(f"ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """
    Главная функция скрипта
    """
    from pathlib import Path
    
    script_dir = Path(__file__).parent
    
    print("=" * 60)
    print("ОБОГАЩЕНИЕ TRIVY SPLOITSCAN")
    print("МОДУЛЬНАЯ ВЕРСИЯ")
    print("=" * 60)
    
    # Ищем отчеты Trivy
    trivy_files = list(script_dir.glob("*.json"))
    trivy_files = [f for f in trivy_files if not f.name.endswith('_enriched.json')]
    
    if not trivy_files:
        print("Нет отчетов Trivy для обработки")
        return
    
    # Обрабатываем каждый отчет
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