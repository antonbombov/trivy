# setup_config.py
from config_manager import load_config, save_config, setup_directories
from pathlib import Path

def interactive_setup():
    """Интерактивная настройка конфигурации"""
    config = load_config()
    
    print("=" * 50)
    print("НАСТРОЙКА TRIVY SPLOITSCAN")
    print("=" * 50)
    
    print("\n🚀 Настройка SploitScan:")
    print("1. SploitScan установлен как системная команда (доступен через 'sploitscan')")
    print("2. Указать абсолютный путь к sploitscan.py файлу")
    
    choice = input("\nВыберите вариант [1/2]: ").strip()
    
    if choice == "2":
        path = input(f"Введите АБСОЛЮТНЫЙ путь к sploitscan.py [{config['sploitscan_path']}]: ").strip()
        if path:
            config['sploitscan_path'] = path
    else:
        config['sploitscan_path'] = "sploitscan"
    
    print("\n📁 Настройка директорий (введите АБСОЛЮТНЫЕ пути):")
    
    scan_dir = input(f"Директория для отчетов Trivy [{config['scan_directory']}]: ").strip()
    cache_dir = input(f"Директория для кэша SploitScan [{config['cache_directory']}]: ").strip()
    
    if scan_dir:
        config['scan_directory'] = scan_dir
    if cache_dir:
        config['cache_directory'] = cache_dir
    
    # Создаем директории
    scan_dir, cache_dir = setup_directories(config)
    
    # Сохраняем конфиг
    if save_config(config):
        print(f"\n✅ Конфигурация сохранена")
        print(f"📁 Отчеты Trivy: {scan_dir}")
        print(f"💾 Кэш SploitScan: {cache_dir}")
        print(f"🚀 SploitScan: {config['sploitscan_path']}")
        print(f"\n💡 Разместите JSON отчеты Trivy в папке: {scan_dir}")
    else:
        print("\n❌ Ошибка сохранения конфигурации")

if __name__ == "__main__":
    interactive_setup()