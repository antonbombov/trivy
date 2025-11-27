# sploitscan_runner.py
import os
import subprocess
import sys
import time
import shutil
from pathlib import Path
from config_manager import get_sploitscan_path, load_config

def find_existing_json(cve_id, target_dir):
    """Ищет существующий JSON файл для CVE в кэше"""
    json_files = list(target_dir.glob(f"*{cve_id}*.json"))
    if json_files:
        return json_files[0]
    return None

def setup_sploitscan_logging(scan_dir, cve_id):
    """Настраивает логирование вывода sploitscan для конкретного CVE"""
    log_dir = scan_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    
    # Создаем уникальный лог-файл для каждого CVE
    log_file = log_dir / f"sploitscan_{cve_id}.log"
    return log_file

def run_sploitscan(cve_id, target_dir):
    """
    Запускает sploitscan для CVE (кросс-платформенно)
    """
    try:
        config = load_config()
        sploitscan_path = get_sploitscan_path(config)
        
        if not sploitscan_path:
            return {'status': 'failed', 'error': 'SploitScan не найден'}
        
        # Создаем целевую папку
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Проверяем кэш
        existing_file = find_existing_json(cve_id, target_dir)
        if existing_file:
            return {'status': 'cached', 'file': existing_file, 'execution_time': 0}
        
        # Настраиваем логирование для этого CVE
        scan_dir = Path(config['scan_directory'])
        log_file = setup_sploitscan_logging(scan_dir, cve_id)
        
        # Настраиваем окружение
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        
        # Определяем команду и рабочую директорию
        if sploitscan_path.endswith('.py'):
            cmd = ['python', sploitscan_path, "-e", "json", cve_id]
            cwd = Path(sploitscan_path).parent
        else:
            cmd = [sploitscan_path, "-e", "json", cve_id]
            cwd = Path(__file__).parent
        
        # Запускаем sploitscan с записью вывода в лог-файл
        start_time = time.time()
        
        with open(log_file, 'w', encoding='utf-8') as log_f:
            # Записываем информацию о запуске
            log_f.write(f"=== SploitScan execution for {cve_id} ===\n")
            log_f.write(f"Command: {' '.join(cmd)}\n")
            log_f.write(f"Working directory: {cwd}\n")
            log_f.write(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_f.write("=" * 50 + "\n\n")
            
            # Запускаем процесс с перенаправлением вывода в лог-файл
            result = subprocess.run(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,  # объединяем stdout и stderr
                encoding='utf-8',
                env=env,
                cwd=str(cwd),
                timeout=config.get('timeout', 60)
            )
            
            # Записываем информацию о завершении
            log_f.write(f"\n" + "=" * 50 + "\n")
            log_f.write(f"Return code: {result.returncode}\n")
            log_f.write(f"End time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_f.write(f"Execution time: {time.time() - start_time:.2f}s\n")
        
        execution_time = time.time() - start_time
        
        if result.returncode == 0:
            # Ищем созданный файл
            json_files = list(cwd.glob(f"*{cve_id}*.json"))
            
            if json_files:
                source_file = json_files[0]
                target_file = target_dir / source_file.name
                shutil.move(str(source_file), str(target_file))
                return {'status': 'success', 'file': target_file, 'execution_time': execution_time}
            else:
                return {'status': 'failed', 'error': 'JSON файл не создан', 'execution_time': execution_time}
        else:
            return {'status': 'failed', 'error': f'Process exited with code {result.returncode}', 'execution_time': execution_time}
            
    except subprocess.TimeoutExpired:
        # Записываем таймаут в лог
        scan_dir = Path(config['scan_directory'])
        log_file = setup_sploitscan_logging(scan_dir, cve_id)
        with open(log_file, 'a', encoding='utf-8') as log_f:
            log_f.write(f"\n*** TIMEOUT EXPIRED after {config.get('timeout', 60)} seconds ***\n")
        
        return {'status': 'failed', 'error': 'Timeout expired', 'execution_time': config.get('timeout', 60)}
    except Exception as e:
        # Записываем исключение в лог
        scan_dir = Path(config['scan_directory'])
        log_file = setup_sploitscan_logging(scan_dir, cve_id)
        with open(log_file, 'a', encoding='utf-8') as log_f:
            log_f.write(f"\n*** EXCEPTION: {str(e)} ***\n")
        
        return {'status': 'failed', 'error': str(e)}