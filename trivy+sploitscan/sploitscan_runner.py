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
        
        # Запускаем sploitscan
        start_time = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            env=env,
            cwd=str(cwd),
            timeout=config.get('timeout', 60)
        )
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
            error_msg = result.stderr if result.stderr else result.stdout
            return {'status': 'failed', 'error': error_msg[:200], 'execution_time': execution_time}
            
    except subprocess.TimeoutExpired:
        return {'status': 'failed', 'error': 'Timeout expired', 'execution_time': config.get('timeout', 60)}
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}