# main.py
import time
from pathlib import Path
from enrichment_core import enrich_trivy_report
from trivy_html_reporter import generate_trivy_html_report
from config_manager import load_config, setup_directories

def main():
    script_dir = Path(__file__).parent
    config = load_config()
    scan_dir, cache_dir = setup_directories(config)
    
    print("=" * 60)
    print("ОБОГАЩЕНИЕ TRIVY SPLOITSCAN")
    print("ПОЛНАЯ ИНФОРМАЦИЯ ОБ ЭКСПЛОЙТАХ + HTML ОТЧЕТ")
    print("=" * 60)
    
    print(f"📁 Ищем отчеты в: {scan_dir}")
    print(f"📝 Логи SploitScan: {scan_dir / 'logs'} (логи пишутся если CVE не закэширована)")
    
    # Ищем отчеты в указанной папке scan_dir
    trivy_files = list(scan_dir.glob("*.json"))
    
    # Исключаем config.json и уже обогащенные отчеты
    trivy_files = [
        f for f in trivy_files 
        if not f.name.endswith('_enriched.json') 
        and f.name != 'config.json'
    ]
    
    if not trivy_files:
        print(f"❌ Нет отчетов Trivy в папке: {scan_dir}")
        print("💡 Поместите JSON отчеты Trivy в указанную папку")
        return
    
    print(f"📊 Найдено отчетов: {len(trivy_files)}")
    
    for trivy_file in trivy_files:
        print(f"\n🔄 ОБРАБОТКА: {trivy_file.name}")
        print("=" * 40)
        
        start_time = time.time()
        enriched_file = enrich_trivy_report(trivy_file)
        total_time = time.time() - start_time
        
        if enriched_file:
            print(f"✅ УСПЕШНО ЗА {total_time:.1f}с")
            
            # ГЕНЕРАЦИЯ HTML ОТЧЕТА
            print(f"\n🌐 Генерация HTML отчета...")
            html_start_time = time.time()
            
            # ЯВНО УКАЗЫВАЕМ ПУТЬ К ОБОГАЩЕННОМУ ФАЙЛУ ИЗ КОНФИГА
            enriched_path = scan_dir / f"{trivy_file.stem}_enriched.json"
            
            print(f"🔍 Ищем обогащенный отчет: {enriched_path}")
            
            if enriched_path.exists():
                html_file = generate_trivy_html_report(enriched_path)
                html_time = time.time() - html_start_time
                
                if html_file:
                    print(f"✅ HTML отчет создан за {html_time:.1f}с: {html_file.name}")
                else:
                    print(f"❌ Ошибка создания HTML отчета")
            else:
                print(f"❌ Обогащенный файл не найден: {enriched_path}")
                
        else:
            print(f"❌ ОШИБКА")

if __name__ == "__main__":
    main()