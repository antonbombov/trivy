from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from webdriver_manager.chrome import ChromeDriverManager
import time
import json

def setup_driver():
    """Настройка Chrome драйвера"""
    chrome_options = Options()
    # chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

def wait_for_results(driver, cve_id):
    """Ожидание загрузки результатов"""
    print("Ожидаем загрузки результатов...")
    
    # Ждем появления элементов с результатами
    wait = WebDriverWait(driver, 15)
    
    try:
        # Ждем появления карточек с результатами
        results_selector = ".card, [class*='result'], [class*='item'], [class*='exploit']"
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, results_selector)))
        print("✓ Результаты загружены")
    except:
        print("⚠ Результаты не найдены по селектору, продолжаем...")
    
    # Даем дополнительное время для полной загрузки
    time.sleep(3)

def extract_exploit_data(driver):
    """Извлечение данных об эксплойтах"""
    exploits = []
    
    print("Извлекаем данные об эксплойтах...")
    
    # Попробуем разные селекторы для карточек
    selectors = [
        ".card",
        "div[class*='card']",
        "div[class*='result']", 
        "div[class*='item']",
        "div[class*='exploit']",
        "#search-results div",
        ".search-results div"
    ]
    
    for selector in selectors:
        try:
            cards = driver.find_elements(By.CSS_SELECTOR, selector)
            if cards:
                print(f"Найдено элементов с '{selector}': {len(cards)}")
                
                for card in cards:
                    try:
                        text = card.text.strip()
                        if text and len(text) > 50:  # Только значимые блоки
                            print(f"\n--- Найден блок ---")
                            print(f"Текст: {text[:200]}...")
                            
                            # Ищем ссылки в блоке
                            card_links = card.find_elements(By.TAG_NAME, "a")
                            for link in card_links:
                                href = link.get_attribute("href")
                                if href and not href.startswith(('javascript:', '#', 'https://sploitus.com/#')):
                                    link_text = link.text.strip()
                                    print(f"  Внешняя ссылка: {link_text} -> {href}")
                                    
                                    exploits.append({
                                        'text': text[:300],
                                        'url': href,
                                        'link_text': link_text
                                    })
                    except Exception as e:
                        continue
        except:
            continue
    
    return exploits

def get_sploitus_data(cve_id):
    driver = setup_driver()
    
    try:
        print(f"Загружаем страницу для {cve_id}...")
        url = f"https://sploitus.com/?query={cve_id}"
        driver.get(url)
        
        # Ждем загрузки и взаимодействуем со страницей
        wait_for_results(driver, cve_id)
        
        # Сохраняем отладочную информацию
        driver.save_screenshot("sploitus_screenshot.png")
        with open("sploitus_source.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        
        # Пробуем кликнуть на вкладку Exploits если есть
        try:
            exploit_tab = driver.find_element(By.CSS_SELECTOR, "a[href='#exploits'], a[data-id='exploits']")
            driver.execute_script("arguments[0].click();", exploit_tab)
            print("✓ Переключились на вкладку Exploits")
            time.sleep(2)
        except:
            print("⚠ Не удалось переключиться на вкладку Exploits")
        
        # Извлекаем данные
        exploits = extract_exploit_data(driver)
        
        # Если не нашли, пробуем альтернативный метод
        if not exploits:
            print("Пробуем альтернативный метод поиска...")
            exploits = find_external_links(driver)
        
        return exploits
        
    except Exception as e:
        print(f"Ошибка: {e}")
        return []
    finally:
        driver.quit()

def find_external_links(driver):
    """Поиск всех внешних ссылок на странице"""
    print("Поиск всех внешних ссылок...")
    exploits = []
    
    all_links = driver.find_elements(By.TAG_NAME, "a")
    external_domains = ['github.com', 'exploit-db.com', 'packetstormsecurity.com', 
                       'cxsecurity.com', '0day.today', 'vulners.com']
    
    for link in all_links:
        href = link.get_attribute("href")
        if href and any(domain in href for domain in external_domains):
            text = link.text.strip()
            if text:
                exploits.append({
                    'text': text,
                    'url': href
                })
                print(f"Найдена внешняя ссылка: {text} -> {href}")
    
    return exploits

def main():
    cve = "CVE-2025-59246"
    print(f"Поиск эксплойтов для {cve}")
    print("=" * 50)
    
    results = get_sploitus_data(cve)
    
    print(f"\n=== ФИНАЛЬНЫЕ РЕЗУЛЬТАТЫ ДЛЯ {cve} ===")
    if results:
        print(f"Найдено {len(results)} эксплойтов:")
        for i, exploit in enumerate(results, 1):
            print(f"\n{i}. URL: {exploit['url']}")
            print(f"   Описание: {exploit.get('text', 'N/A')}")
            if exploit.get('link_text'):
                print(f"   Текст ссылки: {exploit['link_text']}")
    else:
        print("❌ Внешние ссылки на эксплойты не найдены")
        print("\nВозможные причины:")
        print("- Для этой CVE нет публичных эксплойтов")
        print("- Требуется авторизация")
        print("- Данные загружаются через сложный JavaScript")
        print("\nПроверьте файлы:")
        print("- sploitus_screenshot.png - скриншот страницы")
        print("- sploitus_source.html - исходный код")

if __name__ == "__main__":
    main()