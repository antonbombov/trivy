#!/usr/bin/env python3
import requests
import json
import yaml
from typing import Dict, List, Optional
import urllib3

# Отключаем предупреждения о SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DefectDojoEnricher:
    def __init__(self, config_path: str = "config.yaml"):
        self.load_config(config_path)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {self.config['defectdojo']['api_key']}",
            "Content-Type": "application/json"
        })
        self.session.verify = False
    
    def load_config(self, config_path: str):
        """Загрузка конфигурации из YAML файла"""
        try:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Ошибка: Файл конфигурации {config_path} не найден")
            exit(1)
        except yaml.YAMLError as e:
            print(f"Ошибка в формате конфигурационного файла: {e}")
            exit(1)
    
    def parse_trivy_json_report(self, file_path: str, for_risk_accept: bool = False) -> Dict[str, Dict]:
        """Парсинг JSON отчета Trivy"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Ошибка загрузки JSON отчета: {e}")
            return {}
        
        filtered_cves = {}
        total_vulnerabilities = 0
        
        results = report_data.get("Results", [])
        print(f"Найдено Results: {len(results)}")
        
        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])
            total_vulnerabilities += len(vulnerabilities)
            
            for vulnerability in vulnerabilities:
                severity = vulnerability.get("Severity", "").upper()
                github_pocs = vulnerability.get("sploitscan", {}).get("exploit", {}).get("github", {}).get("pocs", [])
                
                cve_id = vulnerability.get("VulnerabilityID", "UNKNOWN")
                pkg_name = vulnerability.get("PkgName", "unknown")
                pkg_version = vulnerability.get("InstalledVersion", "unknown")
                
                # Для enrichment фильтруем по severity и эксплойтам
                # Для risk accept берем все CVE
                if for_risk_accept:
                    # Для risk accept не фильтруем по severity и эксплойтам
                    include_cve = True
                else:
                    # Для enrichment используем стандартные фильтры
                    severity_ok = severity in self.config['settings']['severity_levels']
                    exploits_ok = len(github_pocs) > 0 if self.config['settings']['require_exploits'] else True
                    include_cve = severity_ok and exploits_ok
                
                if include_cve:
                    # ПРАВИЛЬНЫЙ ВЫБОР CVSS - как в Trivy
                    cvss_score = "N/A"
                    cvss_sources = vulnerability.get("CVSS", {})
                    
                    # Берем CVSS от источника который определил severity (как Trivy)
                    severity_source = vulnerability.get("SeveritySource", "").lower()
                    
                    if severity_source and cvss_sources.get(severity_source):
                        cvss_score = cvss_sources[severity_source].get("V3Score") or cvss_sources[severity_source].get("V2Score", "N/A")
                    elif cvss_sources.get("nvd"):
                        cvss_score = cvss_sources["nvd"].get("V3Score") or cvss_sources["nvd"].get("V2Score", "N/A")
                    else:
                        # Берем первый попавшийся CVSS
                        for source_name, source_data in cvss_sources.items():
                            score = source_data.get("V3Score") or source_data.get("V2Score")
                            if score:
                                cvss_score = score
                                break
                    
                    # ИСПРАВЛЕННАЯ ЛОГИКА EPSS - безопасная
                    epss_score = 0.0
                    sploitscan_data = vulnerability.get("sploitscan", {})
                    if sploitscan_data:
                        epss_data_list = sploitscan_data.get("epss", {}).get("data", [])
                        if epss_data_list:
                            epss_str = epss_data_list[0].get("epss", "0")
                            try:
                                epss_score = float(epss_str) * 100
                            except (ValueError, TypeError):
                                epss_score = 0.0
                    
                    github_links = [poc.get("html_url") for poc in github_pocs if poc.get("html_url")]
                    
                    # Формируем note только для enrichment
                    if not for_risk_accept:
                        note_text = f"{cve_id} CVSS: {cvss_score} {severity} EPSS: {epss_score:.2f}%\n\nPublic Exploits\nGitHub\n" + "\n".join(github_links)
                    else:
                        note_text = ""  # Для risk accept note не нужен
                    
                    # УНИКАЛЬНЫЙ КЛЮЧ: CVE + пакет + версия + severity
                    unique_key = f"{cve_id}|{pkg_name}|{pkg_version}|{severity}"
                    
                    filtered_cves[unique_key] = {
                        "cve_id": cve_id,
                        "pkg_name": pkg_name,
                        "pkg_version": pkg_version,
                        "note_text": note_text,
                        "severity": severity,
                        "cvss": cvss_score,
                        "epss": epss_score,
                        "cisa_kev": vulnerability.get("cisa_kev", False),
                        "has_exploits": len(github_links) > 0,
                        "github_links": github_links,
                        "github_links_count": len(github_links)
                    }
        
        print(f"Всего CVE в отчете: {total_vulnerabilities}")
        mode = "risk accept" if for_risk_accept else "enrichment"
        print(f"Отфильтровано для {mode}: {len(filtered_cves)} CVE")
        return filtered_cves
    
    def filter_cves_for_risk_accept(self, filtered_cves: Dict[str, Dict]) -> Dict[str, Dict]:
        """Фильтрация CVE для risk accept по quality gates"""
        if 'risk_accept' not in self.config:
            print("Конфигурация risk_accept не найдена")
            return {}
        
        risk_config = self.config['risk_accept']
        level_criteria = risk_config.get('Level', [])
        with_exploits = risk_config.get('WithExploits')  # Может быть True, False или None
        epss_threshold = risk_config.get('EPSS', 100)
        cisa_kev = risk_config.get('CisaKev', False)
        all_required = risk_config.get('AllRequired', False)
        
        print("=== Фильтрация CVE для Risk Accept ===")
        print(f"Критерии: Level={level_criteria}, WithExploits={with_exploits}")
        print(f"EPSS<={epss_threshold}, CisaKev={cisa_kev}, AllRequired={all_required}")
        
        filtered_for_risk = {}
        
        for unique_key, cve_data in filtered_cves.items():
            checks = []
            
            # Проверка уровня severity
            if level_criteria:
                severity_ok = cve_data["severity"] in [l.upper() for l in level_criteria]
                checks.append(("Severity", severity_ok))
                print(f"  {cve_data['cve_id']} - Severity {cve_data['severity']} in {level_criteria}: {severity_ok}")
            
            # Проверка наличия/отсутствия эксплойтов
            if with_exploits is not None:
                exploits_ok = cve_data["has_exploits"] == with_exploits
                checks.append(("Exploits", exploits_ok))
                print(f"  {cve_data['cve_id']} - Exploits {cve_data['has_exploits']} == {with_exploits}: {exploits_ok}")
            
            # Проверка EPSS
            if epss_threshold < 100:
                epss_ok = cve_data["epss"] <= epss_threshold
                checks.append(("EPSS", epss_ok))
                print(f"  {cve_data['cve_id']} - EPSS {cve_data['epss']:.2f} <= {epss_threshold}: {epss_ok}")
            
            # Проверка CISA KEV
            if cisa_kev:
                cisa_ok = cve_data["cisa_kev"]
                checks.append(("CISA KEV", cisa_ok))
                print(f"  {cve_data['cve_id']} - CISA KEV {cve_data['cisa_kev']}: {cisa_ok}")
            
            # Применяем логику "все или любое"
            if all_required:
                # Все условия должны выполняться
                if checks and all(check[1] for check in checks):
                    filtered_for_risk[unique_key] = cve_data
                    print(f"  ✅ {cve_data['cve_id']} - ПРОШЕЛ (AllRequired)")
            else:
                # Любое условие должно выполняться
                if checks and any(check[1] for check in checks):
                    filtered_for_risk[unique_key] = cve_data
                    print(f"  ✅ {cve_data['cve_id']} - ПРОШЕЛ (AnyRequired)")
            print()  # пустая строка для разделения
        
        print(f"Найдено CVE для risk accept: {len(filtered_for_risk)}")
        return filtered_for_risk
    
    def find_finding_ids(self, product_id: int, filtered_cves: Dict[str, Dict]) -> Dict[str, List[int]]:
        """Поиск ID findings по ТОЧНОМУ CVE ID в АКТИВНЫХ Engagement"""
        findings_map = {}
        
        # Получаем список уникальных CVE ID для поиска
        cve_ids = list(set([data["cve_id"] for data in filtered_cves.values()]))
        
        if not cve_ids:
            print("❌ Нет CVE ID для поиска findings")
            return findings_map
            
        print(f"Поиск findings для {len(cve_ids)} уникальных CVE в АКТИВНЫХ Engagement...")
        print("Используется локальная фильтрация из-за бага в DefectDojo API")
        
        # Получаем ВСЕ findings из активных Engagement
        url = f"{self.config['defectdojo']['url']}/api/v2/findings/"
        params = {
            "test__engagement__product": product_id,
            "test__engagement__status": "In Progress",
            "limit": 1000
        }
        
        try:
            response = self.session.get(url, params=params, verify=False)
            if response.status_code == 200:
                data = response.json()
                all_findings = data.get('results', [])
                print(f"Всего findings в активных Engagement: {len(all_findings)}")
                
                # ПРОСТАЯ ЛОГИКА: для каждого finding ищем подходящую запись в filtered_cves
                for finding in all_findings:
                    vuln_ids = finding.get('vulnerability_ids', [])
                    finding_severity = finding.get('severity', '').upper()
                    
                    # Ищем точное соответствие CVE ID в vulnerability_ids
                    for vuln in vuln_ids:
                        cve_id = vuln.get('vulnerability_id')
                        if cve_id in cve_ids:
                            # Ищем запись в filtered_cves с таким же CVE ID и severity
                            matching_entries = [
                                (key, data) for key, data in filtered_cves.items() 
                                if data["cve_id"] == cve_id and data["severity"] == finding_severity
                            ]
                            
                            if matching_entries:
                                # Берем первую подходящую запись (уникальную для этого CVE+severity)
                                unique_key, cve_data = matching_entries[0]
                                
                                if unique_key not in findings_map:
                                    findings_map[unique_key] = []
                                
                                findings_map[unique_key].append(finding['id'])
                                print(f"   НАЙДЕН finding {finding['id']} для {cve_id} ({cve_data['pkg_name']} {cve_data['pkg_version']}) - severity: {finding_severity}")
                            break
                
                # Статистика по найденным CVE
                found_cves = set()
                for unique_key in findings_map.keys():
                    cve_id = filtered_cves[unique_key]["cve_id"]
                    found_cves.add(cve_id)
                
                for cve_id in cve_ids:
                    if cve_id in found_cves:
                        count = sum(len(findings) for key, findings in findings_map.items() 
                                  if filtered_cves[key]["cve_id"] == cve_id)
                        print(f"НАЙДЕНО findings для {cve_id}: {count} шт")
                    else:
                        print(f"НЕ НАЙДЕНО findings для {cve_id}")
                        
            else:
                print(f"Ошибка получения findings: {response.status_code}")
        except Exception as e:
            print(f"Ошибка при поиске findings: {e}")
        
        return findings_map
    
    def risk_accept_findings(self, finding_ids: List[int], reason: str = "Auto-accepted by quality gates") -> int:
        """Принятие риска для списка findings"""
        success_count = 0
        
        for finding_id in finding_ids:
            url = f"{self.config['defectdojo']['url']}/api/v2/findings/{finding_id}/"
            
            try:
                # Шаг 1: Деактивируем finding
                deactivate_response = self.session.patch(url, json={
                    "active": False,
                    "verified": True
                }, verify=False)
                
                if deactivate_response.status_code == 200:
                    # Шаг 2: Принимаем риск
                    risk_response = self.session.patch(url, json={
                        "risk_accepted": True,
                        "risk_acceptance_reason": reason
                    }, verify=False)
                    
                    if risk_response.status_code == 200:
                        print(f"✓ Risk accepted для finding {finding_id}")
                        success_count += 1
                    else:
                        print(f"✗ Ошибка risk accept для finding {finding_id}: {risk_response.status_code}")
                else:
                    print(f"✗ Ошибка деактивации finding {finding_id}: {deactivate_response.status_code}")
                    
            except Exception as e:
                print(f"✗ Ошибка для finding {finding_id}: {e}")
        
        return success_count
    
    def add_note_to_finding(self, finding_id: int, note_text: str) -> bool:
        """Добавление комментария к finding"""
        url = f"{self.config['defectdojo']['url']}/api/v2/findings/{finding_id}/notes/"
        
        try:
            response = self.session.post(url, json={"entry": note_text}, verify=False)
            if response.status_code == 201:
                print(f"Добавлен комментарий к finding {finding_id}")
                return True
            else:
                print(f"Ошибка добавления комментария к finding {finding_id}: {response.status_code}")
                return False
        except Exception as e:
            print(f"Ошибка при добавлении комментария к finding {finding_id}: {e}")
            return False
    
    def run_enrichment(self, product_id: int, json_path: str):
        """Запуск обогащения комментариями"""
        print("=== DefectDojo CVE Enricher ===")
        print("ПОИСК БУДЕТ ВЫПОЛНЕН ТОЛЬКО В АКТИВНЫХ ENGAGEMENT!")
        
        print("Парсинг JSON отчета для enrichment...")
        filtered_cves = self.parse_trivy_json_report(json_path, for_risk_accept=False)
        
        if not filtered_cves:
            print("Не найдено CVE, соответствующих критериям отбора")
            return None, None
        
        # Статистика
        unique_cves = set(data["cve_id"] for data in filtered_cves.values())
        
        print(f"Результаты парсинга для enrichment:")
        print(f"Найдено {len(filtered_cves)} записей CVE с эксплойтами")
        print(f"Уникальных CVE ID: {len(unique_cves)}")
        
        print("Поиск findings в АКТИВНЫХ Engagement DefectDojo...")
        findings_map = self.find_finding_ids(product_id, filtered_cves)
        
        if not findings_map:
            print("Не найдено соответствующих findings в АКТИВНЫХ Engagement")
            return filtered_cves, None
        
        print("Добавление комментариев...")
        success_count = 0
        total_processed = 0
        
        for unique_key, finding_ids in findings_map.items():
            cve_data = filtered_cves[unique_key]
            for finding_id in finding_ids:
                total_processed += 1
                if self.add_note_to_finding(finding_id, cve_data["note_text"]):
                    success_count += 1
        
        print("ИТОГОВЫЙ РЕЗУЛЬТАТ обогащения:")
        print(f"Успешно обработано: {success_count}/{total_processed} findings")
        
        return filtered_cves, findings_map
    
    def run_risk_accept(self, product_id: int, json_path: str):
        """Запуск автоматического принятия рисков"""
        print("\n=== Risk Accept по Quality Gates ===")
        
        # Парсим ВСЕ CVE из отчета (без фильтрации по severity)
        print("Парсинг JSON отчета для risk accept (все CVE)...")
        all_cves = self.parse_trivy_json_report(json_path, for_risk_accept=True)
        
        if not all_cves:
            print("Не найдено CVE в отчете")
            return
        
        # Фильтруем CVE по quality gates
        risk_cves = self.filter_cves_for_risk_accept(all_cves)
        
        if not risk_cves:
            print("❌ Нет CVE, соответствующих критериям risk accept")
            return
        
        # Показываем какие CVE прошли фильтр
        print("✅ CVE, соответствующие политике risk accept:")
        for unique_key, cve_data in risk_cves.items():
            print(f"  - {cve_data['cve_id']} ({cve_data['pkg_name']} {cve_data['pkg_version']}) - severity: {cve_data['severity']}, EPSS: {cve_data['epss']:.2f}%, exploits: {cve_data['has_exploits']}")
        
        # Ищем findings для отфильтрованных CVE
        print("Поиск findings для risk accept...")
        risk_findings_map = self.find_finding_ids(product_id, risk_cves)
        
        if not risk_findings_map:
            print("❌ Не найдено findings для risk accept")
            return
        
        # Собираем все finding IDs для risk accept
        all_finding_ids = []
        for finding_ids in risk_findings_map.values():
            all_finding_ids.extend(finding_ids)
        
        print(f"✅ Найдено findings для risk accept: {len(all_finding_ids)}")
        
        # Показываем какие findings будут приняты
        print("Findings для risk accept:")
        for unique_key, finding_ids in risk_findings_map.items():
            cve_data = risk_cves[unique_key]
            for finding_id in finding_ids:
                print(f"  - Finding {finding_id}: {cve_data['cve_id']} (severity: {cve_data['severity']})")
        
        # Подтверждение пользователя
        confirm = input(f"Вы уверены, что хотите принять риск для {len(all_finding_ids)} findings? (y/N): ")
        if confirm.lower() != 'y':
            print("Risk accept отменен")
            return
        
        # Выполняем risk accept
        success_count = self.risk_accept_findings(all_finding_ids, "Auto-accepted by quality gates")
        
        print(f"🎉 ИТОГ Risk Accept: успешно принято {success_count}/{len(all_finding_ids)} findings")
    
    def run(self):
        """Основной метод запуска"""
        print("DefectDojo Automation Tool")
        print("1 - Обогащение комментариями (exploits)")
        print("2 - Risk Accept по Quality Gates") 
        print("3 - Оба действия")
        
        choice = input("Выберите действие (1/2/3): ").strip()
        
        try:
            product_id = int(input("Enter Product ID: "))
        except ValueError:
            print("Ошибка: Product ID должен быть числом")
            return
        
        json_path = input("Path to JSON report: ")
        
        if choice in ['1', '3']:
            self.run_enrichment(product_id, json_path)
        
        if choice in ['2', '3']:
            self.run_risk_accept(product_id, json_path)

def main():
    enricher = DefectDojoEnricher()
    enricher.run()

if __name__ == "__main__":
    main()