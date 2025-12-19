#!/usr/bin/env python3
import requests
import json
import os
import sys
from typing import Dict, List, Any
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
        "Level": [],
        "WithExploits": null,
        "EPSS": 100,
        "CisaKev": false,
        "AllRequired": false
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
    
    def _extract_exploits_from_sploitscan(self, sploitscan_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Извлекает ссылки на эксплойты из всех источников в sploitscan
        
        Возвращает:
            {
                "github": ["https://github.com/..."],
                "exploitdb": ["https://www.exploit-db.com/..."],
                "nvd": ["https://github.com/..."],
                "metasploit": ["https://github.com/rapid7/..."],
                "vulncheck": [...],
                "packetstorm": [...],
                "hackerone": [...]
            }
        """
        exploits_by_source = {
            "github": [],
            "exploitdb": [],
            "nvd": [],
            "metasploit": [],
            "vulncheck": [],
            "packetstorm": [],
            "hackerone": []
        }
        
        if not sploitscan_data:
            return exploits_by_source
        
        # 1. GitHub Data
        github_data = sploitscan_data.get("GitHub Data", {})
        if isinstance(github_data, dict):
            github_pocs = github_data.get("pocs", [])
            if isinstance(github_pocs, list):
                for poc in github_pocs:
                    if isinstance(poc, dict):
                        html_url = poc.get("html_url")
                        if html_url and isinstance(html_url, str):
                            exploits_by_source["github"].append(html_url)
        
        # 2. ExploitDB Data
        exploitdb_data = sploitscan_data.get("ExploitDB Data", [])
        if isinstance(exploitdb_data, list):
            for exploit in exploitdb_data:
                if isinstance(exploit, dict):
                    # Вариант 1: прямой URL
                    exploit_url = exploit.get("url")
                    if exploit_url and isinstance(exploit_url, str):
                        exploits_by_source["exploitdb"].append(exploit_url)
                    # Вариант 2: формирование URL из ID
                    elif "id" in exploit:
                        exploit_id = str(exploit["id"]).strip()
                        if exploit_id:
                            exploits_by_source["exploitdb"].append(f"https://www.exploit-db.com/exploits/{exploit_id}")
        
        # 3. NVD Data
        nvd_data = sploitscan_data.get("NVD Data", {})
        if isinstance(nvd_data, dict):
            nvd_exploits = nvd_data.get("exploits", [])
            if isinstance(nvd_exploits, list):
                for exploit_url in nvd_exploits:
                    if exploit_url and isinstance(exploit_url, str):
                        exploits_by_source["nvd"].append(exploit_url)
        
        # 4. Metasploit Data
        metasploit_data = sploitscan_data.get("Metasploit Data", {})
        if isinstance(metasploit_data, dict):
            metasploit_modules = metasploit_data.get("modules", [])
            if isinstance(metasploit_modules, list):
                for module in metasploit_modules:
                    if isinstance(module, dict):
                        module_url = module.get("url")
                        if module_url and isinstance(module_url, str):
                            exploits_by_source["metasploit"].append(module_url)
        
        # 5. VulnCheck Data (структура может быть разной, собираем все URL)
        vulncheck_data = sploitscan_data.get("VulnCheck Data", {})
        if isinstance(vulncheck_data, dict):
            # Рекурсивно ищем URL в VulnCheck данных
            self._find_urls_in_dict(vulncheck_data, exploits_by_source["vulncheck"])
        
        # 6. PacketStorm Data
        packetstorm_data = sploitscan_data.get("PacketStorm Data", {})
        if isinstance(packetstorm_data, dict):
            self._find_urls_in_dict(packetstorm_data, exploits_by_source["packetstorm"])
        
        # 7. HackerOne Data
        hackerone_data = sploitscan_data.get("HackerOne Data", {})
        if isinstance(hackerone_data, dict):
            self._find_urls_in_dict(hackerone_data, exploits_by_source["hackerone"])
        
        return exploits_by_source
    
    def _find_urls_in_dict(self, data: Dict, url_list: List[str]):
        """Рекурсивно ищет URL в словаре"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and value.startswith(('http://', 'https://')):
                    url_list.append(value)
                elif isinstance(value, (dict, list)):
                    self._find_urls_in_dict(value, url_list)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._find_urls_in_dict(item, url_list)
    
    def _get_all_exploit_urls(self, exploits_by_source: Dict[str, List[str]]) -> List[str]:
        """Получает все уникальные URL эксплойтов из всех источников"""
        all_urls = []
        seen_urls = set()
        
        for source, urls in exploits_by_source.items():
            for url in urls:
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_urls.append(url)
        
        return all_urls
    
    def _format_exploits_for_note(self, exploits_by_source: Dict[str, List[str]]) -> str:
        """Форматирует информацию об эксплойтах для комментария"""
        note_lines = ["Public Exploits"]
        
        for source, urls in exploits_by_source.items():
            if urls:
                source_name = source.upper()
                note_lines.append(f"\n{source_name}")
                for url in urls[:10]:  # Ограничиваем количество ссылок
                    note_lines.append(f"  {url}")
                if len(urls) > 10:
                    note_lines.append(f"  ... и еще {len(urls) - 10} ссылок")
        
        return "\n".join(note_lines)
    
    def _check_cisa_kev_status(self, sploitscan_data: Dict[str, Any]) -> bool:
        """
        Проверяет CISA KEV статус из данных sploitscan
        
        Новая структура: "CISA Data" вместо "CISA KEV"
        """
        is_cisa_kev = False
        
        # Пробуем оба варианта для обратной совместимости
        cisa_data = sploitscan_data.get("CISA Data", sploitscan_data.get("cisa_kev", {}))
        
        if isinstance(cisa_data, dict):
            # Вариант 1: ключ cisa_status
            cisa_status = cisa_data.get("cisa_status")
            if cisa_status:
                is_cisa_kev = str(cisa_status).strip().upper() == "YES"
            
            # Вариант 2: ключ kev (для обратной совместимости)
            if not is_cisa_kev and "kev" in cisa_data:
                kev_value = cisa_data.get("kev")
                if kev_value:
                    is_cisa_kev = str(kev_value).strip().upper() in ["YES", "TRUE", "1"]
        
        return is_cisa_kev
    
    def parse_trivy_json_report(self, file_path: str, for_risk_accept: bool = False) -> Dict[str, Dict]:
        """Парсинг JSON отчета Trivy с новой структурой sploitscan"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Ошибка загрузки JSON отчета: {e}")
            return {}
        
        filtered_vulns = {}
        total_vulnerabilities = 0
        cisa_kev_count = 0
        
        results = report_data.get("Results", [])
        
        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])
            total_vulnerabilities += len(vulnerabilities)
            
            for vulnerability in vulnerabilities:
                vulnerability_id = vulnerability.get("VulnerabilityID", "UNKNOWN")
                severity = vulnerability.get("Severity", "").upper()
                
                # Получаем данные sploitscan с новой структурой
                sploitscan_data_raw = vulnerability.get("sploitscan")
                
                # ОБРАБОТКА: Если sploitscan_data - список, берем первый элемент
                sploitscan_data = {}
                if isinstance(sploitscan_data_raw, list) and sploitscan_data_raw:
                    sploitscan_data = sploitscan_data_raw[0] if isinstance(sploitscan_data_raw[0], dict) else {}
                elif isinstance(sploitscan_data_raw, dict):
                    sploitscan_data = sploitscan_data_raw
                
                # Извлекаем эксплойты из всех источников
                exploits_by_source = self._extract_exploits_from_sploitscan(sploitscan_data)
                all_exploit_urls = self._get_all_exploit_urls(exploits_by_source)
                has_exploits = len(all_exploit_urls) > 0
                
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
                
                # Проверяем CISA KEV статус (новая структура: "CISA Data")
                is_cisa_kev = False
                if isinstance(sploitscan_data, dict):
                    cisa_data = sploitscan_data.get("CISA Data", sploitscan_data.get("cisa_kev", {}))
                    if isinstance(cisa_data, dict):
                        cisa_status = cisa_data.get("cisa_status")
                        if cisa_status:
                            is_cisa_kev = str(cisa_status).strip().upper() == "YES"
                
                if is_cisa_kev:
                    cisa_kev_count += 1
                
                # Для enrichment фильтруем по severity и эксплойтам
                # Для risk accept берем все уязвимости
                if for_risk_accept:
                    include_vuln = True
                else:
                    severity_ok = severity in self.config['settings']['severity_levels']
                    exploits_ok = has_exploits if self.config['settings']['require_exploits'] else True
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
                    
                    # Получаем EPSS данные (новая структура)
                    epss_score = 0.0
                    epss_data = sploitscan_data.get("EPSS", {})
                    if isinstance(epss_data, dict):
                        epss_data_list = epss_data.get("data", [])
                        if isinstance(epss_data_list, list) and epss_data_list:
                            epss_item = epss_data_list[0]
                            if isinstance(epss_item, dict):
                                epss_str = epss_item.get("epss", "0")
                                try:
                                    epss_score = float(epss_str) * 100
                                except (ValueError, TypeError):
                                    epss_score = 0.0
                    
                    # Форматируем информацию об эксплойтах для комментария
                    exploits_text = ""
                    if not for_risk_accept:
                        exploits_text = self._format_exploits_for_note(exploits_by_source)
                    
                    # Формируем note только для enrichment
                    if not for_risk_accept:
                        note_text = f"{vulnerability_id} ({vuln_type}) CVSS: {cvss_score} {severity} EPSS: {epss_score:.2f}%"
                        if exploits_text:
                            note_text += f"\n\n{exploits_text}"
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
                        "cisa_kev": is_cisa_kev,
                        "has_exploits": has_exploits,
                        "all_exploit_urls": all_exploit_urls,
                        "exploits_by_source": exploits_by_source,
                        "exploit_sources_count": sum(len(urls) for urls in exploits_by_source.values())
                    }
        
        print(f"Всего уязвимостей в отчете: {total_vulnerabilities}")
        print(f"CISA KEV уязвимостей в отчете: {cisa_kev_count}")
        
        # Статистика по типам уязвимостей
        vuln_types_count = {}
        for vuln_data in filtered_vulns.values():
            vuln_type = vuln_data["vuln_type"]
            vuln_types_count[vuln_type] = vuln_types_count.get(vuln_type, 0) + 1
        
        print("Распределение по типам уязвимостей:")
        for vuln_type, count in vuln_types_count.items():
            print(f"  {vuln_type}: {count}")
        
        # Статистика по источникам эксплойтов
        if not for_risk_accept:
            source_stats = {}
            for vuln_data in filtered_vulns.values():
                for source, urls in vuln_data["exploits_by_source"].items():
                    if urls:
                        source_stats[source] = source_stats.get(source, 0) + 1
            
            if source_stats:
                print("Уязвимости с эксплойтами по источникам:")
                for source, count in sorted(source_stats.items()):
                    print(f"  {source}: {count}")
        
        mode = "risk accept" if for_risk_accept else "enrichment"
        print(f"Отфильтровано для {mode}: {len(filtered_vulns)} уязвимостей")
        return filtered_vulns
    
    def filter_vulns_for_risk_accept(self, filtered_vulns: Dict[str, Dict]) -> Dict[str, Dict]:
        """Фильтрация уязвимостей для risk accept по quality gates"""
        if 'risk_accept' not in self.config:
            print("Конфигурация risk_accept не найдена")
            return {}
        
        risk_config = self.config['risk_accept']
        
        # Берем значения из конфига БЕЗ значений по умолчанию
        level_criteria = [l.upper() for l in risk_config.get('Level', [])]
        with_exploits = risk_config.get('WithExploits')
        epss_threshold = risk_config.get('EPSS')
        cisa_kev = risk_config.get('CisaKev')
        all_required = risk_config.get('AllRequired')
        
        print("=== Фильтрация уязвимостей для Risk Accept ===")
        print(f"Критерии: Level={level_criteria}")
        print(f"WithExploits={with_exploits}, EPSS={epss_threshold}")
        print(f"CisaKev={cisa_kev}, AllRequired={all_required}")
        
        filtered_for_risk = {}
        
        for unique_key, vuln_data in filtered_vulns.items():
            checks = []
            
            # Проверка уровня severity (только если указаны уровни)
            if level_criteria:
                severity_ok = vuln_data["severity"] in level_criteria
                checks.append(("Severity", severity_ok))
            
            # Проверка наличия/отсутствия эксплойтов (только если указано)
            if with_exploits is not None:
                exploits_ok = vuln_data["has_exploits"] == with_exploits
                checks.append(("Exploits", exploits_ok))
            
            # Проверка EPSS (только если указан порог)
            if epss_threshold is not None:
                epss_ok = vuln_data["epss"] <= epss_threshold
                checks.append(("EPSS", epss_ok))
            
            # Проверка CISA KEV (только если указано)
            if cisa_kev is not None:
                cisa_ok = vuln_data["cisa_kev"] == cisa_kev
                checks.append(("CISA KEV", cisa_ok))
            
            # Если нет ни одного критерия - пропускаем
            if not checks:
                continue
            
            # Применяем логику "все или любое"
            if all_required:
                # Все указанные условия должны выполняться
                if all(check[1] for check in checks):
                    filtered_for_risk[unique_key] = vuln_data
            else:
                # Любое указанное условие должно выполняться
                if any(check[1] for check in checks):
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
                        
                        # Проверяем vulnerability_ids
                        for vuln_obj in vuln_ids_in_finding:
                            vuln_id_from_finding = vuln_obj.get('vulnerability_id', '')
                            if not vuln_id_from_finding:
                                continue
                            
                            vuln_id_upper = vuln_id_from_finding.upper()
                            
                            # Ищем в нашем словаре
                            if vuln_id_upper in vuln_lookup:
                                unique_key, vuln_data = vuln_lookup[vuln_id_upper]
                                
                                # НЕ ПРОВЕРЯЕМ SEVERITY! Просто добавляем finding
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
            exploit_info = f"exploits: {vuln_data['has_exploits']}"
            if vuln_data['has_exploits']:
                exploit_info += f" (sources: {vuln_data['exploit_sources_count']})"
            
            print(f"  - {vuln_data['vuln_id']} ({vuln_data['vuln_type']}) ({vuln_data['pkg_name']} {vuln_data['pkg_version']}) - severity: {vuln_data['severity']}, EPSS: {vuln_data['epss']:.2f}%, {exploit_info}")
        
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