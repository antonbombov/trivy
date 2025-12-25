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
    output_dir = input(
        f"Директория для результатов (JSON+HTML+Логи) [{config.get('output_directory', 'Results')}]: ").strip()

    if scan_dir:
        config['scan_directory'] = scan_dir
    if cache_dir:
        config['cache_directory'] = cache_dir
    if output_dir:
        config['output_directory'] = output_dir

    print("\n⚙️  Настройка параметров кэширования:")

    max_days = input(f"Максимальный возраст файлов в кэше (дней) [{config.get('cache_max_days', 30)}]: ").strip()
    if max_days:
        try:
            config['cache_max_days'] = int(max_days)
        except ValueError:
            print(f"⚠️  Некорректное значение, используется по умолчанию: {config.get('cache_max_days', 30)}")

    # Создаем директории
    scan_dir, cache_dir, output_dir = setup_directories(config)

    # Создаем папку для логов в output_directory
    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Сохраняем конфиг
    if save_config(config):
        print(f"\n✅ Конфигурация сохранена")
        print(f"📁 Отчеты Trivy: {scan_dir}")
        print(f"💾 Кэш SploitScan: {cache_dir} (макс. возраст: {config.get('cache_max_days', 30)} дней)")
        print(f"📄 Результаты: {output_dir}")
        print(f"🚀 SploitScan: {config['sploitscan_path']}")
        print(f"\n💡 Разместите JSON отчеты Trivy в папке: {scan_dir}")
        print(f"💡 Итоговые отчеты и логи будут сохраняться в: {output_dir}")
        print(f"💡 Старые файлы в кэше будут автоматически удаляться при запуске")
    else:
        print("\n❌ Ошибка сохранения конфигурации")

if __name__ == "__main__":
    interactive_setup()