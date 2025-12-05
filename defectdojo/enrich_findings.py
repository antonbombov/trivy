#!/usr/bin/env python3
import requests
import json
import os
import re
import sys
from typing import Dict, List, Optional
import urllib3

# Отключаем предупреждения о SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DefectDojoEnricher:
    def __init__(self, config_path: str = "config.json"):
        self.load_config(config_path)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {self.config['defectdojo']['api_key']}",
            "Content-Type": "application/json"
        })
        self.session.verify = False
    
    def load_config(self, config_path: str):
        """Загрузка конфигурации из JSON файла"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Ошибка: Файл конфигурации {config_path} не найден")
            print(f"Создайте файл {config_path} с содержимым:")
            print('''{
    "defectdojo": {
        "url": "https://your-defectdojo-instance.com",
        "api_key": "your-api-key-here"
    },
    "settings": {
        "severity_levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "require_exploits": true
    },
    "risk_accept": {
        "Level": ["Medium", "Low"],
        "WithExploits": false,
        "EPSS": 100,
        "CisaKev": false,
        "AllRequired": true
    },
    "automation": {
        "mode": null,
        "auto_confirm": false,
        "product_id": null,
        "json_path": null
    }
}''')
            exit(1)
        except json.JSONDecodeError as e:
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
        
        filtered_vulns = {}
        total_vulnerabilities = 0
        
        results = report_data.get("Results", [])
        
        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])
            total_vulnerabilities += len(vulnerabilities)
            
            for vulnerability in vulnerabilities:
                vulnerability_id = vulnerability.get("VulnerabilityID", "UNKNOWN")
                severity = vulnerability.get("Severity", "").upper()
                github_pocs = vulnerability.get("sploitscan", {}).get("exploit", {}).get("github", {}).get("pocs", [])
                
                pkg_name = vulnerability.get("PkgName", "unknown")
                pkg_version = vulnerability.get("InstalledVersion", "unknown")
                
                # Определяем тип уязвимости по ID
                vuln_type = "UNKNOWN"
                if vulnerability_id.startswith("CVE-"):
                    vuln_type = "CVE"
                elif vulnerability_id.startswith("GHSA-"):
                    vuln_type = "GHSA"
                elif vulnerability_id.startswith("DSA-") or vulnerability_id.startswith("DLSA-"):
                    vuln_type = "DSA"
                elif vulnerability_id.startswith("ELSA-"):
                    vuln_type = "ELSA"
                elif vulnerability_id.startswith("RUSTSEC-"):
                    vuln_type = "RUSTSEC"
                elif vulnerability_id.startswith("PYSEC-"):
                    vuln_type = "PYSEC"
                elif vulnerability_id.startswith("GMS-"):
                    vuln_type = "GMS"
                elif "OSV-" in vulnerability_id:
                    vuln_type = "OSV"
                elif vulnerability_id.startswith("SNYK-"):
                    vuln_type = "SNYK"
                elif vulnerability_id.startswith("UBUNTU-"):
                    vuln_type = "UBUNTU"
                elif vulnerability_id.startswith("ALAS-"):
                    vuln_type = "ALAS"
                
                # Для enrichment фильтруем по severity и эксплойтам
                # Для risk accept берем все уязвимости
                if for_risk_accept:
                    include_vuln = True
                else:
                    severity_ok = severity in self.config['settings']['severity_levels']
                    exploits_ok = len(github_pocs) > 0 if self.config['settings']['require_exploits'] else True
                    include_vuln = severity_ok and exploits_ok
                
                if include_vuln:
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
                    
                    # Безопасная логика EPSS
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
                        note_text = f"{vulnerability_id} ({vuln_type}) CVSS: {cvss_score} {severity} EPSS: {epss_score:.2f}%\n\nPublic Exploits\nGitHub\n" + "\n".join(github_links)
                    else:
                        note_text = ""
                    
                    # УНИКАЛЬНЫЙ КЛЮЧ: ID + пакет + версия + severity
                    unique_key = f"{vulnerability_id}|{pkg_name}|{pkg_version}|{severity}"
                    
                    filtered_vulns[unique_key] = {
                        "vuln_id": vulnerability_id,
                        "vuln_type": vuln_type,
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
        
        print(f"Всего уязвимостей в отчете: {total_vulnerabilities}")
        
        # Статистика по типам уязвимостей
        vuln_types_count = {}
        for vuln_data in filtered_vulns.values():
            vuln_type = vuln_data["vuln_type"]
            vuln_types_count[vuln_type] = vuln_types_count.get(vuln_type, 0) + 1
        
        print("Распределение по типам уязвимостей:")
        for vuln_type, count in vuln_types_count.items():
            print(f"  {vuln_type}: {count}")
        
        mode = "risk accept" if for_risk_accept else "enrichment"
        print(f"Отфильтровано для {mode}: {len(filtered_vulns)} уязвимостей")
        return filtered_vulns
    
    def filter_vulns_for_risk_accept(self, filtered_vulns: Dict[str, Dict]) -> Dict[str, Dict]:
        """Фильтрация уязвимостей для risk accept по quality gates"""
        if 'risk_accept' not in self.config:
            print("Конфигурация risk_accept не найдена")
            return {}
        
        risk_config = self.config['risk_accept']
        level_criteria = risk_config.get('Level', [])
        with_exploits = risk_config.get('WithExploits')
        epss_threshold = risk_config.get('EPSS', 100)
        cisa_kev = risk_config.get('CisaKev', False)
        all_required = risk_config.get('AllRequired', False)
        
        print("=== Фильтрация уязвимостей для Risk Accept ===")
        print(f"Критерии: Level={level_criteria}, WithExploits={with_exploits}")
        print(f"EPSS<={epss_threshold}, CisaKev={cisa_kev}, AllRequired={all_required}")
        
        filtered_for_risk = {}
        
        for unique_key, vuln_data in filtered_vulns.items():
            checks = []
            
            # Проверка уровня severity
            if level_criteria:
                severity_ok = vuln_data["severity"] in [l.upper() for l in level_criteria]
                checks.append(("Severity", severity_ok))
            
            # Проверка наличия/отсутствия эксплойтов
            if with_exploits is not None:
                exploits_ok = vuln_data["has_exploits"] == with_exploits
                checks.append(("Exploits", exploits_ok))
            
            # Проверка EPSS
            if epss_threshold < 100:
                epss_ok = vuln_data["epss"] <= epss_threshold
                checks.append(("EPSS", epss_ok))
            
            # Проверка CISA KEV
            if cisa_kev:
                cisa_ok = vuln_data["cisa_kev"]
                checks.append(("CISA KEV", cisa_ok))
            
            # Применяем логику "все или любое"
            if all_required:
                if checks and all(check[1] for check in checks):
                    filtered_for_risk[unique_key] = vuln_data
            else:
                if checks and any(check[1] for check in checks):
                    filtered_for_risk[unique_key] = vuln_data
        
        print(f"Найдено уязвимостей для risk accept: {len(filtered_for_risk)}")
        return filtered_for_risk
    
    def find_finding_ids(self, product_id: int, filtered_vulns: Dict[str, Dict]) -> Dict[str, List[int]]:
        """Поиск ID АКТИВНЫХ findings по уязвимостям в АКТИВНЫХ Engagement"""
        findings_map = {}
        
        # Получаем список уникальных ID уязвимостей для поиска
        vuln_ids = list(set([data["vuln_id"] for data in filtered_vulns.values()]))
        
        if not vuln_ids:
            print("❌ Нет ID уязвимостей для поиска findings")
            return findings_map
            
        print(f"Поиск АКТИВНЫХ findings для {len(vuln_ids)} уникальных уязвимостей в АКТИВНЫХ Engagement...")
        
        # Ищем АКТИВНЫЕ engagement
        engagements_url = f"{self.config['defectdojo']['url']}/api/v2/engagements/"
        engagements_params = {
            "product": product_id,
            "status": "In Progress",
            "limit": 100
        }
        
        active_engagement_ids = []
        try:
            engagements_response = self.session.get(engagements_url, params=engagements_params, verify=False)
            if engagements_response.status_code == 200:
                engagements_data = engagements_response.json()
                active_engagement_ids = [eng['id'] for eng in engagements_data.get('results', [])]
                print(f"Найдено АКТИВНЫХ Engagement: {len(active_engagement_ids)}")
            else:
                print(f"Ошибка получения активных Engagement: {engagements_response.status_code}")
                return findings_map
        except Exception as e:
            print(f"Ошибка при получении активных Engagement: {e}")
            return findings_map
        
        if not active_engagement_ids:
            print("❌ Не найдено активных Engagement в продукте")
            return findings_map
        
        # Создаем словарь для быстрого поиска
        vuln_lookup = {}
        for key, data in filtered_vulns.items():
            vuln_id_upper = data["vuln_id"].upper()
            vuln_lookup[vuln_id_upper] = (key, data)
        
        # Ищем АКТИВНЫЕ findings в КАЖДОМ активном engagement
        for engagement_id in active_engagement_ids:
            print(f"Поиск findings в Engagement {engagement_id}...")
            
            url = f"{self.config['defectdojo']['url']}/api/v2/findings/"
            params = {
                "test__engagement": engagement_id,
                "active": "true",
                "limit": 1000
            }
            
            try:
                response = self.session.get(url, params=params, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    findings_in_engagement = data.get('results', [])
                    
                    if not findings_in_engagement:
                        continue
                    
                    # Ищем совпадения по уязвимостям
                    for finding in findings_in_engagement:
                        finding_id = finding['id']
                        vuln_ids_in_finding = finding.get('vulnerability_ids', [])
                        finding_severity = finding.get('severity', '').upper()
                        
                        # Проверяем vulnerability_ids
                        for vuln_obj in vuln_ids_in_finding:
                            vuln_id_from_finding = vuln_obj.get('vulnerability_id', '')
                            if not vuln_id_from_finding:
                                continue
                            
                            vuln_id_upper = vuln_id_from_finding.upper()
                            
                            # Ищем в нашем словаре
                            if vuln_id_upper in vuln_lookup:
                                unique_key, vuln_data = vuln_lookup[vuln_id_upper]
                                
                                # Проверяем совпадение severity
                                if vuln_data["severity"] == finding_severity:
                                    if unique_key not in findings_map:
                                        findings_map[unique_key] = []
                                    
                                    if finding_id not in findings_map[unique_key]:
                                        findings_map[unique_key].append(finding_id)
                                        print(f"    ✓ Найден АКТИВНЫЙ finding {finding_id} для {vuln_id_from_finding}")
                
                else:
                    print(f"  Ошибка получения findings из Engagement {engagement_id}: {response.status_code}")
            except Exception as e:
                print(f"  Ошибка при поиске findings в Engagement {engagement_id}: {e}")
        
        # Статистика по найденным уязвимостям
        print(f"\n=== РЕЗУЛЬТАТЫ ПОИСКА ===")
        
        found_count = 0
        for vuln_id in vuln_ids:
            findings_for_vuln = []
            for unique_key, finding_ids in findings_map.items():
                if filtered_vulns[unique_key]["vuln_id"] == vuln_id:
                    findings_for_vuln.extend(finding_ids)
            
            if findings_for_vuln:
                vuln_type = next((data["vuln_type"] for data in filtered_vulns.values() if data["vuln_id"] == vuln_id), "UNKNOWN")
                found_count += 1
                print(f"✅ НАЙДЕНО АКТИВНЫХ findings для {vuln_id} ({vuln_type}): {len(findings_for_vuln)} шт")
            else:
                vuln_type = next((data["vuln_type"] for data in filtered_vulns.values() if data["vuln_id"] == vuln_id), "UNKNOWN")
                print(f"❌ НЕ НАЙДЕНО АКТИВНЫХ findings для {vuln_id} ({vuln_type})")
        
        total_findings = sum(len(ids) for ids in findings_map.values())
        print(f"\nИТОГО: найдено {found_count} из {len(vuln_ids)} уязвимостей, всего {total_findings} findings")
        
        return findings_map
    
    def risk_accept_findings(self, finding_ids: List[int], reason: str = "Auto-accepted by quality gates") -> int:
        """Принятие риска для списка findings"""
        success_count = 0
        
        for finding_id in finding_ids:
            url = f"{self.config['defectdojo']['url']}/api/v2/findings/{finding_id}/"
            
            try:
                response = self.session.patch(url, json={
                    "active": False,
                    "verified": True,
                    "risk_accepted": True,
                    "risk_acceptance_reason": reason
                }, verify=False)
                
                if response.status_code == 200:
                    print(f"✓ Risk accepted для finding {finding_id}")
                    success_count += 1
                else:
                    print(f"✗ Ошибка risk accept для finding {finding_id}: {response.status_code} - {response.text}")
                    
            except Exception as e:
                print(f"✗ Ошибка при risk accept finding {finding_id}: {e}")
        
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
        filtered_vulns = self.parse_trivy_json_report(json_path, for_risk_accept=False)
        
        if not filtered_vulns:
            print("Не найдено уязвимостей, соответствующих критериям отбора")
            return None, None
        
        unique_vulns = set(data["vuln_id"] for data in filtered_vulns.values())
        
        print(f"Результаты парсинга для enrichment:")
        print(f"Найдено {len(filtered_vulns)} записей уязвимостей с эксплойтами")
        print(f"Уникальных ID уязвимостей: {len(unique_vulns)}")
        
        print("Поиск findings в АКТИВНЫХ Engagement DefectDojo...")
        findings_map = self.find_finding_ids(product_id, filtered_vulns)
        
        if not findings_map:
            print("Не найдено соответствующих findings в АКТИВНЫХ Engagement")
            return filtered_vulns, None
        
        print("Добавление комментариев...")
        success_count = 0
        total_processed = 0
        
        for unique_key, finding_ids in findings_map.items():
            vuln_data = filtered_vulns[unique_key]
            for finding_id in finding_ids:
                total_processed += 1
                if self.add_note_to_finding(finding_id, vuln_data["note_text"]):
                    success_count += 1
        
        print("ИТОГОВЫЙ РЕЗУЛЬТАТ обогащения:")
        print(f"Успешно обработано: {success_count}/{total_processed} findings")
        
        return filtered_vulns, findings_map
    
    def run_risk_accept(self, product_id: int, json_path: str, auto_confirm: bool = False):
        """Запуск автоматического принятия рисков"""
        print("\n=== Risk Accept по Quality Gates ===")
        
        print("Парсинг JSON отчета для risk accept (все уязвимости)...")
        all_vulns = self.parse_trivy_json_report(json_path, for_risk_accept=True)
        
        if not all_vulns:
            print("Не найдено уязвимостей в отчете")
            return
        
        risk_vulns = self.filter_vulns_for_risk_accept(all_vulns)
        
        if not risk_vulns:
            print("❌ Нет уязвимостей, соответствующих критериям risk accept")
            return
        
        print("✅ Уязвимости, соответствующие политике risk accept:")
        for unique_key, vuln_data in risk_vulns.items():
            print(f"  - {vuln_data['vuln_id']} ({vuln_data['vuln_type']}) ({vuln_data['pkg_name']} {vuln_data['pkg_version']}) - severity: {vuln_data['severity']}, EPSS: {vuln_data['epss']:.2f}%, exploits: {vuln_data['has_exploits']}")
        
        print("Поиск findings для risk accept...")
        risk_findings_map = self.find_finding_ids(product_id, risk_vulns)
        
        if not risk_findings_map:
            print("❌ Не найдено findings для risk accept")
            return
        
        all_finding_ids = []
        for finding_ids in risk_findings_map.values():
            all_finding_ids.extend(finding_ids)
        
        print(f"✅ Найдено findings для risk accept: {len(all_finding_ids)}")
        
        print("Findings для risk accept:")
        for unique_key, finding_ids in risk_findings_map.items():
            vuln_data = risk_vulns[unique_key]
            for finding_id in finding_ids:
                print(f"  - Finding {finding_id}: {vuln_data['vuln_id']} ({vuln_data['vuln_type']}) (severity: {vuln_data['severity']})")
        
        # Подтверждение пользователя или автоматическое подтверждение
        if not auto_confirm:
            confirm = input(f"Вы уверены, что хотите принять риск для {len(all_finding_ids)} findings? (y/N): ")
            if confirm.lower() != 'y':
                print("Risk accept отменен")
                return
        else:
            print(f"Автоматическое подтверждение: принимаем риск для {len(all_finding_ids)} findings")
        
        # Выполняем risk accept
        success_count = self.risk_accept_findings(all_finding_ids, "Auto-accepted by quality gates")
        
        print(f"🎉 ИТОГ Risk Accept: успешно принято {success_count}/{len(all_finding_ids)} findings")
    
    def run(self):
        """Основной метод запуска"""
        print("DefectDojo Automation Tool")
        
        # Получаем настройки автоматизации
        automation_config = self.config.get('automation', {})
        
        # Режим работы
        mode = automation_config.get('mode')
        if mode is None:
            print("1 - Обогащение комментариями (exploits)")
            print("2 - Risk Accept по Quality Gates") 
            print("3 - Оба действия")
            choice = input("Выберите действие (1/2/3): ").strip()
        else:
            choice = str(mode)
            print(f"Режим работы из конфига: {mode}")
        
        # Product ID
        product_id = automation_config.get('product_id')
        if product_id is None:
            try:
                product_id = int(input("Enter Product ID: "))
            except ValueError:
                print("Ошибка: Product ID должен быть числом")
                return
        else:
            print(f"Product ID из конфига: {product_id}")
        
        # Путь к JSON отчету
        json_path = automation_config.get('json_path')
        if json_path is None:
            json_path = input("Path to JSON report: ")
        else:
            print(f"Путь к отчету из конфига: {json_path}")
        
        # Проверяем существование файла отчета
        if not os.path.exists(json_path):
            print(f"Ошибка: Файл отчета не найден: {json_path}")
            return
        
        # Автоматическое подтверждение
        auto_confirm = automation_config.get('auto_confirm', False)
        
        # Выполняем выбранные действия
        if choice in ['1', '3']:
            self.run_enrichment(product_id, json_path)
        
        if choice in ['2', '3']:
            self.run_risk_accept(product_id, json_path, auto_confirm)

def main():
    # Можно передать путь к конфигу как аргумент командной строки
    config_path = "config.json"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    enricher = DefectDojoEnricher(config_path)
    enricher.run()

if __name__ == "__main__":
    main()