# trivy_html_reporter.py
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from html_templates import get_base_html, get_css_styles, get_javascript

def generate_trivy_html_report(enriched_trivy_path, output_dir=None):
    """
    Генерирует HTML отчет из обогащенного отчета Trivy в стиле SploitScan
    """
    try:
        # Загружаем обогащенный отчет
        with open(enriched_trivy_path, 'r', encoding='utf-8-sig') as f:
            trivy_data = json.load(f)
        
        # Определяем путь для сохранения
        if output_dir is None:
            output_dir = Path(__file__).parent
        
        output_path = output_dir / f"{enriched_trivy_path.stem}_report.html"
        
        # Собираем статистику и данные
        stats, grouped_vulnerabilities = collect_statistics_and_group_data(trivy_data)
        
        # Генерируем HTML
        html_content = generate_html_content(trivy_data, stats, grouped_vulnerabilities)
        
        # Сохраняем файл
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML отчет создан: {output_path}")
        return output_path
        
    except Exception as e:
        print(f"ОШИБКА генерации HTML отчета: {e}")
        return None

def collect_statistics_and_group_data(trivy_data):
    """
    Собирает статистику и группирует уязвимости по разделам и пакетам
    """
    stats = {
        'total_cves': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'unknown': 0,
        'with_exploits': 0,
        'cisa_kev': 0
    }
    
    grouped_vulnerabilities = defaultdict(lambda: defaultdict(list))
    processed_cves = set()  # Для отслеживания уникальных CVE
    
    if 'Results' in trivy_data:
        for result in trivy_data['Results']:
            # Используем Type для группировки, если есть, иначе Target
            section_type = result.get('Type', result.get('Class', 'Unknown'))
            target = result.get('Target', 'Unknown')
            
            # Создаем понятное имя раздела
            if section_type and section_type != 'Unknown':
                section_name = f"{section_type} ({target})"
            else:
                section_name = target
            
            if 'Vulnerabilities' in result:
                # СОРТИРОВКА: Сортируем уязвимости по severity перед добавлением
                vulnerabilities_sorted = sorted(
                    result['Vulnerabilities'],
                    key=lambda x: get_severity_weight(x.get('Severity', 'UNKNOWN')),
                    reverse=True  # По убыванию критичности
                )
                
                for vuln in vulnerabilities_sorted:
                    if 'VulnerabilityID' in vuln:
                        cve_id = vuln['VulnerabilityID']
                        
                        # Учитываем каждое CVE только один раз для статистики
                        if cve_id not in processed_cves:
                            processed_cves.add(cve_id)
                            stats['total_cves'] += 1
                            
                            # Статистика по severity (только для уникальных CVE)
                            severity = vuln.get('Severity', 'UNKNOWN').upper()
                            if severity == 'CRITICAL':
                                stats['critical'] += 1
                            elif severity == 'HIGH':
                                stats['high'] += 1
                            elif severity == 'MEDIUM':
                                stats['medium'] += 1
                            elif severity == 'LOW':
                                stats['low'] += 1
                            else:
                                stats['unknown'] += 1
                            
                            # Статистика по эксплойтам (только для уникальных CVE)
                            if has_real_exploits(vuln):
                                stats['with_exploits'] += 1
                            
                            # Статистика по CISA KEV (только для уникальных CVE)
                            if is_cisa_kev(vuln):
                                stats['cisa_kev'] += 1
                        
                        # Группировка по пакетам (все уязвимости, включая дубли)
                        pkg_name = vuln.get('PkgName', 'Unknown Package')
                        grouped_vulnerabilities[section_name][pkg_name].append(vuln)
    
    return stats, grouped_vulnerabilities

def get_severity_weight(severity):
    """
    Возвращает вес severity для сортировки (чем выше вес, тем критичнее)
    """
    severity_weights = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'UNKNOWN': 0
    }
    return severity_weights.get(severity.upper(), 0)

def has_real_exploits(vuln):
    """Проверяет, есть ли реальные эксплойты (игнорируя packetstorm search)"""
    sploitscan = vuln.get('sploitscan', {})
    
    # ПРОВЕРКА НА ОШИБКУ SPLOITSCAN
    if 'error' in sploitscan:
        return False
        
    exploit = sploitscan.get('exploit', {})
    
    # Проверяем наличие реальных эксплойтов, исключая packetstorm search
    github_pocs = exploit.get('github', {}).get('pocs', [])
    exploitdb_list = exploit.get('ExploitDB Data', [])
    vulncheck_data = exploit.get('vulncheck', {})
    
    # Считаем только если есть реальные PoC, а не просто поисковые ссылки
    if (github_pocs and len(github_pocs) > 0) or \
       (exploitdb_list and len(exploitdb_list) > 0) or \
       (vulncheck_data and len(vulncheck_data) > 0):
        return True
    
    # Проверяем наличие Metasploit модулей
    if 'metasploit' in str(exploit).lower():
        return True
    
    return False

def is_cisa_kev(vuln):
    """Проверяет, есть ли CVE в CISA KEV"""
    sploitscan = vuln.get('sploitscan', {})
    
    # ПРОВЕРКА НА ОШИБКУ SPLOITSCAN
    if 'error' in sploitscan:
        return False
        
    cisa_data = sploitscan.get('cisa_kev', {})
    cisa_status = cisa_data.get('cisa_status', 'Not Listed')
    # Расширяем проверку на разные варианты обозначения "да"
    return cisa_status in ['Listed', 'Yes', 'YES', 'listed', 'yes']

def format_epss(epss_score):
    """Форматирует EPSS score в проценты"""
    if epss_score == 'N/A':
        return 'N/A'
    try:
        # Умножаем на 100 и форматируем с 2 знаками после запятой
        return f"{float(epss_score) * 100:.2f}%"
    except (ValueError, TypeError):
        return 'N/A'

def get_cvss_data(vuln):
    """Извлекает CVSS данные с учетом приоритетов вендоров"""
    cvss_data = vuln.get('CVSS', {})
    severity_source = vuln.get('SeveritySource', '')
    vendor_severity = vuln.get('VendorSeverity', {})
    
    # 1. Пытаемся взять из того же источника что и Severity
    if severity_source and severity_source in cvss_data:
        data = cvss_data[severity_source]
        v3_score = data.get('V3Score')
        v2_score = data.get('V2Score')
        v3_vector = data.get('V3Vector')
        v2_vector = data.get('V2Vector')
        
        # Предпочитаем V3 над V2
        if v3_score is not None:
            return v3_score, v3_vector or v2_vector or 'N/A'
        elif v2_score is not None:
            return v2_score, v2_vector or 'N/A'
    
    # 2. Ищем источник с максимальным VendorSeverity
    if vendor_severity:
        # Сортируем вендоров по убыванию VendorSeverity
        sorted_vendors = sorted(vendor_severity.items(), key=lambda x: x[1], reverse=True)
        for vendor, score in sorted_vendors:
            if vendor in cvss_data:
                data = cvss_data[vendor]
                v3_score = data.get('V3Score')
                v2_score = data.get('V2Score')
                v3_vector = data.get('V3Vector')
                v2_vector = data.get('V2Vector')
                
                # Предпочитаем V3 над V2
                if v3_score is not None:
                    return v3_score, v3_vector or v2_vector or 'N/A'
                elif v2_score is not None:
                    return v2_score, v2_vector or 'N/A'
    
    # 3. Fallback: берем первого попавшегося (оригинальная логика)
    for source, data in cvss_data.items():
        v3_score = data.get('V3Score')
        v2_score = data.get('V2Score')
        v3_vector = data.get('V3Vector')
        v2_vector = data.get('V2Vector')
        
        # Предпочитаем V3 над V2
        if v3_score is not None:
            return v3_score, v3_vector or v2_vector or 'N/A'
        elif v2_score is not None:
            return v2_score, v2_vector or 'N/A'
    
    return 'N/A', 'N/A'

def generate_html_content(trivy_data, stats, grouped_vulnerabilities):
    """
    Генерирует полный HTML контент
    """
    main_content = generate_main_content(stats, grouped_vulnerabilities)
    
    html = get_base_html().format(
        main_content=main_content,
        total_cves=stats['total_cves'],
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        css_styles=get_css_styles(),
        javascript=get_javascript()
    )
    
    return html

def generate_main_content(stats, grouped_vulnerabilities):
    """
    Генерирует основное содержимое отчета
    """
    # Статистические карточки
    stats_cards = generate_stats_cards(stats)
    
    # Контент с группировкой по разделам
    vulnerabilities_content = generate_vulnerabilities_content(grouped_vulnerabilities)
    
    return f"""
    <div class="grid grid-cols-1 lg:grid-cols-[290px_minmax(0,1fr)] gap-6">
      <!-- Sidebar -->
      <aside class="no-print hidden lg:block">
        {generate_sidebar(grouped_vulnerabilities)}
      </aside>

      <!-- Main column -->
      <section>
        <!-- Summary dashboard -->
        <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
          {stats_cards}
        </div>
        
        <!-- Counter for visible cards -->
        <div id="visibleCounter" class="mb-4 px-3 py-2 bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300 rounded-md text-sm font-medium hidden">
          <span id="visibleCount">0</span> of <span id="totalCount">{stats['total_cves']}</span> vulnerabilities visible
        </div>

        <!-- Vulnerabilities by section -->
        <div class="space-y-6">
          {vulnerabilities_content}
        </div>
      </section>
    </div>
    """

def generate_stats_cards(stats):
    """Генерирует карточки со статистикой"""
    cards = [
        f'<div class="card"><div class="card-body"><div class="muted text-xs">Total CVEs</div><div class="mt-2 text-2xl font-semibold">{stats["total_cves"]}</div></div></div>',
        f'<div class="card"><div class="card-body"><div class="muted text-xs">Critical</div><div class="mt-2 text-2xl font-semibold text-red-600">{stats["critical"]}</div></div></div>',
        f'<div class="card"><div class="card-body"><div class="muted text-xs">High</div><div class="mt-2 text-2xl font-semibold text-orange-600">{stats["high"]}</div></div></div>',
        f'<div class="card"><div class="card-body"><div class="muted text-xs">With Exploits</div><div class="mt-2 text-2xl font-semibold text-purple-600">{stats["with_exploits"]}</div></div></div>'
    ]
    return '\n'.join(cards)

def generate_sidebar(grouped_vulnerabilities):
    """Генерирует боковую панель с навигацией и фильтрами"""
    sections_list = []
    for section_name in grouped_vulnerabilities.keys():
        section_id = section_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
        sections_list.append(f'<a href="#{section_id}" class="block rounded px-2 py-1 text-sm hover:bg-gray-100 dark:hover:bg-gray-700">{section_name}</a>')
    
    sections_html = '\n'.join(sections_list)
    
    return f"""
    <div class="sticky sticky-sidebar">
      <!-- Filters -->
      <div class="card mb-4">
        <div class="card-header">
          <h2 class="text-sm font-semibold tracking-wide uppercase muted">Filters</h2>
        </div>
        <div class="card-body space-y-3">
          <div>
            <label class="block text-xs font-medium muted mb-1">Quick search (CVE ID or Package)</label>
            <input id="searchInput" type="text" placeholder="Search CVE or package…" class="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-gray-800" />
          </div>
          
          <div>
            <label class="block text-xs font-medium muted mb-1">Priority</label>
            <div class="flex flex-wrap gap-2">
              <button data-prio="A+" class="prio chip priority-A+">A+</button>
              <button data-prio="A" class="prio chip priority-A">A</button>
              <button data-prio="B" class="prio chip priority-B">B</button>
              <button data-prio="C" class="prio chip priority-C">C</button>
              <button data-prio="D" class="prio chip priority-D">D</button>
            </div>
          </div>
          
          <div>
            <label class="block text-xs font-medium muted mb-1">Severity</label>
            <div class="flex flex-wrap gap-2">
              <button data-severity="CRITICAL" class="severity chip bg-red-100 text-red-700 dark:bg-red-800/40 dark:text-red-100">Critical</button>
              <button data-severity="HIGH" class="severity chip bg-orange-100 text-orange-700 dark:bg-orange-800/40 dark:text-orange-100">High</button>
              <button data-severity="MEDIUM" class="severity chip bg-yellow-100 text-yellow-700 dark:bg-yellow-800/40 dark:text-yellow-100">Medium</button>
              <button data-severity="LOW" class="severity chip bg-green-100 text-green-700 dark:bg-green-800/40 dark:text-green-100">Low</button>
            </div>
          </div>
          
          <div>
            <label class="block text-xs font-medium muted mb-1">EPSS ≥ %</label>
            <input id="filterEPSS" type="number" min="0" max="100" step="0.01" placeholder="0.00%" class="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-gray-800" />
          </div>
          
          <!-- ДОБАВЛЕНО: Status filter -->
          <div>
            <label class="block text-xs font-medium muted mb-1">Status</label>
            <div class="flex flex-wrap gap-2">
              <button data-status="fixed" class="status chip bg-green-100 text-green-700 dark:bg-green-800/40 dark:text-green-100">Fixed</button>
              <button data-status="affected" class="status chip bg-red-100 text-red-700 dark:bg-red-800/40 dark:text-red-100">Affected</button>
              <button data-status="will_not_fix" class="status chip bg-gray-100 text-gray-700 dark:bg-gray-800/40 dark:text-gray-100">Will not fix</button>
              <button data-status="unknown" class="status chip bg-yellow-100 text-yellow-700 dark:bg-yellow-800/40 dark:text-yellow-100">Unknown</button>
            </div>
          </div>
          
          <div class="flex items-center gap-2">
            <input id="filterCISA" type="checkbox" class="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-600 dark:border-gray-600" />
            <label for="filterCISA" class="text-sm">CISA KEV only</label>
          </div>
          
          <div class="flex items-center gap-2">
            <input id="filterExploit" type="checkbox" class="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-600 dark:border-gray-600" />
            <label for="filterExploit" class="text-sm">Has public exploits</label>
          </div>
          
          <div class="pt-2">
            <button id="resetFilters" class="w-full text-xs text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">Reset filters</button>
          </div>
        </div>
      </div>

      <!-- Sections Navigation -->
      <div class="card">
        <div class="card-header">
          <h2 class="text-sm font-semibold tracking-wide uppercase muted">Sections</h2>
        </div>
        <div class="card-body">
          <div class="scroll-area overflow-y-auto space-y-1">
            {sections_html}
          </div>
        </div>
      </div>
    </div>
    """

def generate_vulnerabilities_content(grouped_vulnerabilities):
    """Генерирует контент с уязвимостями, сгруппированными по разделам"""
    content_parts = []
    
    for section_name, packages in grouped_vulnerabilities.items():
        section_id = section_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
        
        # Заголовок раздела
        section_content = f"""
        <article id="{section_id}" class="card">
          <div class="card-header">
            <h2 class="text-lg font-semibold">{section_name}</h2>
          </div>
          <div class="card-body">
        """
        
        # Уязвимости по пакетам
        for pkg_name, vulnerabilities in packages.items():
            section_content += generate_package_section(pkg_name, vulnerabilities)
        
        section_content += """
          </div>
        </article>
        """
        content_parts.append(section_content)
    
    return '\n'.join(content_parts)

def generate_package_section(pkg_name, vulnerabilities):
    """Генерирует секцию для одного пакета"""
    # ДОПОЛНИТЕЛЬНАЯ СОРТИРОВКА: Сортируем уязвимости внутри пакета
    vulnerabilities_sorted = sorted(
        vulnerabilities,
        key=lambda x: get_severity_weight(x.get('Severity', 'UNKNOWN')),
        reverse=True  # По убыванию критичности
    )
    
    package_content = f"""
    <div class="mb-6 last:mb-0">
      <h3 class="font-semibold text-md mb-3 border-b pb-2">{pkg_name}</h3>
      <div class="space-y-3">
    """

    for vuln in vulnerabilities_sorted:
        package_content += generate_vulnerability_card(vuln)
    
    package_content += """
      </div>
    </div>
    """
    return package_content

def generate_vulnerability_card(vuln):
    """Генерирует детальную карточку для одной уязвимости"""
    cve_id = vuln.get('VulnerabilityID', 'Unknown')
    severity = vuln.get('Severity', 'UNKNOWN')
    description = vuln.get('Description', 'No description available')
    # Экранируем описание
    description = description.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    
    pkg_name = vuln.get('PkgName', 'Unknown Package')
    installed_version = vuln.get('InstalledVersion', 'Unknown')
    fixed_version = vuln.get('FixedVersion', 'Not fixed')
    status = vuln.get('Status', 'Unknown')
    references = vuln.get('References', [])
    
    # CVSS данные (ИСПРАВЛЕННАЯ ЛОГИКА)
    cvss_score, cvss_vector = get_cvss_data(vuln)
    
    # Определяем цвет для CVSS
    cvss_color = 'gray'
    if cvss_score != 'N/A':
        try:
            score = float(cvss_score)
            if score >= 9.0:
                cvss_color = 'red'
            elif score >= 7.0:
                cvss_color = 'orange'
            elif score >= 4.0:
                cvss_color = 'yellow'
            else:
                cvss_color = 'green'
        except (ValueError, TypeError):
            cvss_color = 'gray'
    
    # Данные из SploitScan
    sploitscan = vuln.get('sploitscan', {})
    
    # ОБРАБОТКА ОШИБКИ SPLOITSCAN
    if 'error' in sploitscan:
        priority = 'Unknown'
        epss_score = 'N/A'
        cisa_status = 'Not Listed'
        ransomware_use = 'N/A'
        github_pocs = []
        exploitdb_list = []
        metasploit_modules = []
        has_exploits = False
        is_cisa_listed = False
    else:
        priority = sploitscan.get('priority', {}).get('Priority', 'Unknown')
        
        # БЕЗОПАСНОЕ ПОЛУЧЕНИЕ EPSS ДАННЫХ
        epss_data_list = sploitscan.get('epss', {}).get('data', [])
        epss_data = epss_data_list[0] if epss_data_list else {}
        epss_score = epss_data.get('epss', 'N/A')
        
        cisa_data = sploitscan.get('cisa_kev', {})
        cisa_status = cisa_data.get('cisa_status', 'Not Listed')
        ransomware_use = cisa_data.get('ransomware_use', 'N/A')
        
        # Определяем, находится ли CVE в списке CISA KEV
        # Используем более широкую проверку для разных вариантов значений
        is_cisa_listed = cisa_status in ['Listed', 'Yes', 'YES', 'listed', 'yes']
        
        # Exploit данные
        exploit_data = sploitscan.get('exploit', {})
        github_pocs = exploit_data.get('github', {}).get('pocs', [])
        exploitdb_list = exploit_data.get('ExploitDB Data', [])
        metasploit_modules = []
        
        # Ищем Metasploit модули
        for key, value in exploit_data.items():
            if 'metasploit' in str(key).lower() or 'metasploit' in str(value).lower():
                if isinstance(value, list):
                    metasploit_modules.extend(value)
                else:
                    metasploit_modules.append(value)
        
        has_exploits = has_real_exploits(vuln)
    
    return f"""
    <div class="vulnerability-card border rounded-lg p-4 hover:shadow-md transition-shadow mb-4" 
         data-cve="{cve_id}" 
         data-package="{pkg_name}" 
         data-prio="{priority}" 
         data-severity="{severity}"
         data-epss="{epss_score if epss_score != 'N/A' else '0'}"
         data-cisa="{str(is_cisa_listed).lower()}" 
         data-expl="{str(has_exploits).lower()}"
         data-status="{status.lower()}">
      
      <!-- Заголовок карточки -->
      <div class="flex justify-between items-start mb-3">
        <div class="flex items-center gap-2 flex-wrap">
          <h4 class="font-medium text-lg">{cve_id}</h4>
          <span class="badge bg-{cvss_color}-100 text-{cvss_color}-700 dark:bg-{cvss_color}-800/40 dark:text-{cvss_color}-100">CVSS: {cvss_score}</span>
          {f'<span class="badge bg-red-100 text-red-700 dark:bg-red-800/40 dark:text-red-100">{severity}</span>' if severity == 'CRITICAL' else ''}
          {f'<span class="badge bg-orange-100 text-orange-700 dark:bg-orange-800/40 dark:text-orange-100">{severity}</span>' if severity == 'HIGH' else ''}
          {f'<span class="badge bg-yellow-100 text-yellow-700 dark:bg-yellow-800/40 dark:text-yellow-100">{severity}</span>' if severity == 'MEDIUM' else ''}
          {f'<span class="badge bg-green-100 text-green-700 dark:bg-green-800/40 dark:text-green-100">{severity}</span>' if severity == 'LOW' else ''}
          <span class="pill priority-{priority}">{priority}</span>
        </div>
        <div class="text-right text-sm">
          <div class="muted">EPSS: {format_epss(epss_score)}</div>
          <div class="muted">Status: {status}</div>
        </div>
      </div>
      
      <!-- Базовая информация -->
      <div class="mb-3">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <span class="font-medium">Package:</span> {pkg_name}
          </div>
          <div>
            <span class="font-medium">Version:</span> {installed_version}
          </div>
          <div>
            <span class="font-medium">Fixed in:</span> {fixed_version}
          </div>
          <div>
            <span class="font-medium">CISA KEV:</span> 
            {f'<span class="badge bg-green-100 text-green-700 dark:bg-green-800/40 dark:text-green-100">{cisa_status}</span>' if is_cisa_listed else f'<span class="badge bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200">{cisa_status}</span>'}
          </div>
        </div>
      </div>
      
      <!-- Описание -->
      <div class="mb-3">
        <p class="text-sm">{description}</p>
      </div>
      
      <!-- Детальная информация (раскрывающаяся) -->
      <details class="mt-3">
        <summary class="cursor-pointer font-medium text-sm text-brand-600 hover:text-brand-700">
          Show detailed information
        </summary>
        
        <div class="mt-3 space-y-4 border-t pt-3">
          
          <!-- CVSS Vector -->
          <div>
            <h5 class="font-medium mb-2">CVSS Vector</h5>
            <div class="text-sm">
              <code class="text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded">{cvss_vector}</code>
            </div>
          </div>
          
          <!-- EPSS Score -->
          <div>
            <h5 class="font-medium mb-2">EPSS Score</h5>
            <div class="text-sm">
              <span class="muted">Probability:</span> {format_epss(epss_score)}
            </div>
          </div>
          
          <!-- CISA KEV Details -->
          {f'''
          <div>
            <h5 class="font-medium mb-2">CISA KEV Details</h5>
            <div class="text-sm">
              <div><span class="muted">Ransomware Use:</span> {ransomware_use}</div>
            </div>
          </div>
          ''' if is_cisa_listed else ''}
          
          <!-- Exploits -->
          {generate_exploits_section(github_pocs, exploitdb_list, metasploit_modules) if has_exploits else '''
          <div>
            <h5 class="font-medium mb-2">Public Exploits</h5>
            <div class="muted text-sm">No public exploits found.</div>
          </div>
          '''}
          
          <!-- References -->
          {generate_references_section(references) if references else ''}
          
        </div>
      </details>
    </div>
    """
    
def generate_exploits_section(github_pocs, exploitdb_list, metasploit_modules):
    """Генерирует секцию с эксплойтами"""
    exploits_content = '<div><h5 class="font-medium mb-2">Public Exploits</h5><div class="space-y-3">'
    
    # GitHub PoCs
    if github_pocs:
        exploits_content += '''
        <div>
          <div class="font-medium text-sm mb-1">GitHub</div>
          <ul class="list-disc pl-5 space-y-1 text-sm">
        '''
        for poc in github_pocs[:5]:
            url = poc.get('html_url', '')
            if url:
                exploits_content += f'<li><a href="{url}" target="_blank" class="link">{url}</a></li>'
        exploits_content += '</ul></div>'
    
    # ExploitDB Data
    if exploitdb_list:
        exploits_content += '''
        <div>
          <div class="font-medium text-sm mb-1">ExploitDB</div>
          <ul class="list-disc pl-5 space-y-1 text-sm">
        '''
        for exploit in exploitdb_list[:5]:
            if isinstance(exploit, dict):
                url = exploit.get('url', '')
                if url and 'packetstorm' not in url.lower():
                    exploits_content += f'<li><a href="{url}" target="_blank" class="link">{url}</a></li>'
        exploits_content += '</ul></div>'
    
    # Metasploit
    if metasploit_modules:
        exploits_content += '''
        <div>
          <div class="font-medium text-sm mb-1">Metasploit</div>
          <ul class="list-disc pl-5 space-y-1 text-sm">
        '''
        for module in metasploit_modules[:3]:
            if isinstance(module, dict):
                name = module.get('name', module.get('title', 'Metasploit Module'))
                exploits_content += f'<li>{name}</li>'
            else:
                exploits_content += f'<li>{module}</li>'
        exploits_content += '</ul></div>'
    
    exploits_content += '</div></div>'
    return exploits_content

def generate_references_section(references):
    """Генерирует секцию с ссылками"""
    references_content = '''
    <div>
      <h5 class="font-medium mb-2">References</h5>
      <ul class="list-disc pl-5 space-y-1 text-sm">
    '''
    
    for ref in references[:10]:  # Ограничиваем 10 ссылками
        references_content += f'<li><a href="{ref}" target="_blank" class="link">{ref}</a></li>'
    
    references_content += '</ul></div>'
    return references_content    

def main():
    """
    Основная функция для тестирования
    """
    script_dir = Path(__file__).parent
    enriched_files = list(script_dir.glob("*_enriched.json"))
    
    if not enriched_files:
        print("Нет обогащенных отчетов Trivy")
        return
    
    for enriched_file in enriched_files:
        print(f"Генерация HTML отчета для: {enriched_file.name}")
        generate_trivy_html_report(enriched_file)

if __name__ == "__main__":
    main()