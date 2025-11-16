<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    {{- if . }}
    <style>
      * { font-family: Arial, Helvetica, sans-serif; font-size: medium; }
      h1, .scanner-info { text-align: center; }
      .group-header th { font-size: 200%; }
      .sub-header th { font-size: 150%; }
      table, th, td { border: 1px solid black; border-collapse: collapse; white-space: nowrap; padding: .3em; }
      table { margin: 0 auto; }
      .severity { text-align: center; font-weight: bold; color: #fafafa; }
      .severity-LOW .severity { background-color: #5fbb31; }
      .severity-MEDIUM .severity { background-color: #e9c600; }
      .severity-HIGH .severity { background-color: #ff8800; }
      .severity-CRITICAL .severity { background-color: #e40000; }
      .severity-UNKNOWN .severity { background-color: #747474; }
      .severity-LOW { background-color: #5fbb3160; }
      .severity-MEDIUM { background-color: #e9c60060; }
      .severity-HIGH { background-color: #ff880060; }
      .severity-CRITICAL { background-color: #e4000060; }
      .severity-UNKNOWN { background-color: #74747460; }
      table tr td:first-of-type { font-weight: bold; }
      .links a, .links[data-more-links=on] a { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px; }
      .links[data-more-links=off] a:nth-of-type(1n+5) { display: none; }
      a.toggle-more-links { cursor: pointer; }
      .description { white-space: normal; }
      .filter-header { position: relative; cursor: pointer; background-color: #f0f0f0; }
      .filter-dropdown { display: none; position: absolute; top: 100%; left: 0; background: white; border: 1px solid #ccc; padding: 10px; z-index: 1000; min-width: 150px; max-height: 200px; overflow-y: auto; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
      .filter-dropdown input[type="text"] { width: 100%; margin-bottom: 5px; padding: 3px; border: 1px solid #ccc; }
      .filter-dropdown label { display: block; margin: 2px 0; cursor: pointer; font-size: 12px; }
      .filter-dropdown input[type="checkbox"] { margin-right: 5px; }
      .filter-icon { margin-left: 5px; font-size: 12px; color: #666; font-weight: normal; }
      .reset-filters { padding: 8px 15px; margin: 10px auto; display: block; background-color: #dc3545; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 14px; }
      .reset-filters:hover { background-color: #c82333; }
      .select-visible-btn { margin-top: 5px; padding: 3px 8px; font-size: 11px; cursor: pointer; }
      .hidden { display: none; }
      .scanner-info { margin: 10px auto; color: #666; font-size: 14px; }
    </style>
    <title>{{- escapeXML (index . 0).Target }} - Trivy Report - {{ now }}</title>
    <script>
      const FILTER_TYPES = ['package', 'vulnerabilityId', 'severity', 'status'];
      let filtersInitialized = false;
      const selectedValues = Object.fromEntries(FILTER_TYPES.map(type => [type, new Set()]));
      const allFilterCheckboxes = new Map(FILTER_TYPES.map(type => [type, new Set()]));

      // Вспомогательные функции
      const forEachElement = (selector, callback) => document.querySelectorAll(selector).forEach(callback);
      const hideAllDropdowns = () => forEachElement('.filter-dropdown', d => d.style.display = 'none');
      const createElement = (tag, props) => Object.assign(document.createElement(tag), props);

      window.onload = function() {
        initLinks();
        initExcelFilters();
        
        document.addEventListener('click', (e) => {
          if (!e.target.closest('.filter-header') && !e.target.closest('.filter-dropdown')) {
            hideAllDropdowns();
          }
        });

        document.getElementById('resetFilters').addEventListener('click', resetAllFilters);
      };

      function initLinks() {
        forEachElement('td.links', linkCell => {
          const links = [...linkCell.querySelectorAll('a')].sort((a, b) => a.href > b.href ? 1 : -1);
          links.forEach((link, idx) => {
            if (links.length > 3 && idx === 3) {
              linkCell.appendChild(createElement('a', {
                innerText: "Toggle more links", href: "#toggleMore", className: "toggle-more-links"
              }));
            }
            linkCell.appendChild(link);
          });
        });

        forEachElement('a.toggle-more-links', toggleLink => {
          toggleLink.onclick = () => {
            const expanded = toggleLink.parentElement.getAttribute("data-more-links");
            toggleLink.parentElement.setAttribute("data-more-links", expanded === "on" ? "off" : "on");
            return false;
          };
        });
      }

      function initExcelFilters() {
        if (filtersInitialized) return;
        
        const allValues = Object.fromEntries(FILTER_TYPES.map(type => [type, new Set()]));

        // Сбор данных из таблицы
        forEachElement('table tr:not(.group-header):not(.sub-header)', row => {
          if (row.cells.length >= 8) {
            FILTER_TYPES.forEach((type, index) => {
              allValues[type].add(row.cells[index].textContent.trim());
            });
          }
        });

        // Инициализация значений и создание фильтров
        FILTER_TYPES.forEach(type => {
          allValues[type].forEach(value => selectedValues[type].add(value));
          forEachElement(`th[data-column="${type}"]`, header => {
            createFilterDropdown(header, type, Array.from(allValues[type]).sort());
          });
        });

        filtersInitialized = true;
      }

      function createFilterDropdown(header, filterType, values) {
        header.querySelector('.filter-dropdown')?.remove();

        const validValues = values.filter(v => v && v !== '');
        const dropdown = createElement('div', {
          className: 'filter-dropdown',
          innerHTML: `
            <input type="text" class="filter-search" placeholder="Search...">
            <div class="filter-options">
              ${validValues.map(value => `
                <label><input type="checkbox" class="filter-checkbox" value="${value}" checked>${value}</label>
              `).join('')}
            </div>
          `
        });

        header.appendChild(dropdown);
        header.classList.add('filter-header');
        header.appendChild(createElement('span', { className: 'filter-icon', innerHTML: '[v]' }));

        // Очистка текста заголовка
        const headerText = header.childNodes[0];
        if (headerText?.nodeType === Node.TEXT_NODE) {
          headerText.textContent = headerText.textContent.replace(/ \[v\]/g, '').trim();
        }

        const allLabels = dropdown.querySelectorAll('label');
        const allCheckboxes = dropdown.querySelectorAll('.filter-checkbox');

        // Регистрация чекбоксов
        allCheckboxes.forEach(checkbox => allFilterCheckboxes.get(filterType).add(checkbox));

        // Поиск
        dropdown.querySelector('.filter-search').addEventListener('input', function() {
          const searchValue = this.value.toLowerCase();
          allLabels.forEach(label => {
            label.style.display = label.textContent.toLowerCase().includes(searchValue) ? 'block' : 'none';
          });
        });

        // Кнопка выбора видимых
        const selectVisibleBtn = createElement('button', {
          innerText: "Select Only Visible", className: "select-visible-btn"
        });
        selectVisibleBtn.addEventListener('click', () => selectOnlyVisible(filterType, allCheckboxes, allLabels));
        dropdown.appendChild(selectVisibleBtn);

        // Обработчики чекбоксов
        allCheckboxes.forEach(checkbox => {
          checkbox.addEventListener('change', function() {
            updateFilterState(filterType, this.value, this.checked);
          });
        });

        // Управление dropdown
        dropdown.addEventListener('click', (e) => e.stopPropagation());
        header.addEventListener('click', (e) => {
          e.stopPropagation();
          const isVisible = dropdown.style.display === 'block';
          hideAllDropdowns();
          dropdown.style.display = isVisible ? 'none' : 'block';
          if (!isVisible) setTimeout(() => dropdown.querySelector('.filter-search').focus(), 10);
        });
      }

      function selectOnlyVisible(filterType, allCheckboxes, allLabels) {
        const searchInput = allCheckboxes[0]?.closest('.filter-dropdown')?.querySelector('.filter-search');
        const searchValue = searchInput?.value.toLowerCase() || '';
        
        selectedValues[filterType].clear();
        allCheckboxes.forEach(checkbox => checkbox.checked = false);
        
        allLabels.forEach(label => {
          if (label.style.display !== 'none' && label.textContent.toLowerCase().includes(searchValue)) {
            const checkbox = label.querySelector('input[type="checkbox"]');
            checkbox.checked = true;
            selectedValues[filterType].add(checkbox.value);
          }
        });
        
        applyFilters();
      }

      function updateFilterState(filterType, value, checked) {
        checked ? selectedValues[filterType].add(value) : selectedValues[filterType].delete(value);
        syncCheckboxes(filterType, value, checked);
        applyFilters();
      }

      function syncCheckboxes(filterType, value, checked) {
        allFilterCheckboxes.get(filterType)?.forEach(checkbox => {
          if (checkbox.value === value && checkbox.checked !== checked) {
            checkbox.checked = checked;
          }
        });
      }

      function applyFilters() {
        forEachElement('table tr:not(.group-header):not(.sub-header)', row => {
          if (row.cells.length >= 8) {
            const rowData = [...row.cells].slice(0,4).map(c => c.textContent.trim());
            const showRow = FILTER_TYPES.every((type, index) => selectedValues[type].has(rowData[index]));
            row.classList.toggle('hidden', !showRow);
          }
        });
      }

      function resetAllFilters() {
        FILTER_TYPES.forEach(type => {
          selectedValues[type].clear();
          allFilterCheckboxes.get(type)?.forEach(checkbox => {
            checkbox.checked = true;
            selectedValues[type].add(checkbox.value);
          });
        });
        applyFilters();
      }
    </script>
    <link rel="stylesheet" type="text/css" href="/entensys-xscript/abl.css" />
</head>
<body>
    <h1>{{- escapeXML (index . 0).Target }} - Trivy Report - {{ now }}</h1>
    <div class="scanner-info">Generated by Trivy Scanner <!-- TRIVY_VERSION --></div>

    {{- if . }}
      {{- $allVulns := list }}
      {{- range $result := . }}{{ range $vuln := .Vulnerabilities }}{{ $allVulns = append $allVulns $vuln }}{{ end }}{{ end }}
      
      {{- if gt (len $allVulns) 0 }}
        {{- $severityCount := dict }}
        {{- range $vuln := $allVulns }}
          {{- $severity := $vuln.Vulnerability.Severity }}
          {{- $vulnID := $vuln.VulnerabilityID }}
          {{- $current := index $severityCount $severity | default dict }}
          {{- $current = set $current $vulnID true }}
          {{- $severityCount = set $severityCount $severity $current }}
        {{- end }}
        
        <div style="text-align: center;">
          <h2>Vulnerability Summary</h2>
          <table class="summary-table">
            <tr><th>Severity</th><th>Unique CVE Count</th></tr>
            {{- range $severity := list "CRITICAL" "HIGH" "MEDIUM" "LOW" "UNKNOWN" }}
              {{- $count := len (index $severityCount $severity | default dict) }}
              <tr class="severity-{{ $severity }}"><td class="severity">{{ $severity }}</td><td style="font-weight: bold;">{{ $count }}</td></tr>
            {{- end }}
            {{- $total := 0 }}{{ range $severity, $vulns := $severityCount }}{{ $total = add $total (len $vulns) }}{{ end }}
            <tr style="background-color: #f0f0f0; font-weight: bold;"><td>TOTAL</td><td>{{ $total }}</td></tr>
          </table>
        </div>
      {{- end }}
    {{- end }}

    <button class="reset-filters" id="resetFilters">Reset All Filters</button>

    <table>
    {{- range $result := . }}
      <tr class="group-header"><th colspan="8">{{ .Type | toString | escapeXML }}</th></tr>
      {{- if (eq (len .Vulnerabilities) 0) }}
        <tr><th colspan="8">No Vulnerabilities found</th></tr>
      {{- else }}
        <tr class="sub-header">
          <th data-column="package">Package</th><th data-column="vulnerabilityId">Vulnerability ID</th>
          <th data-column="severity">Severity</th><th data-column="status">Status</th>
          <th>Installed Version</th><th>Fixed Version</th><th>Description</th><th>Links</th>
        </tr>
        {{- range $severity_level := list "CRITICAL" "HIGH" "MEDIUM" "LOW" "UNKNOWN"}}
          {{- range $vuln := $result.Vulnerabilities }}
            {{- if (eq (escapeXML $vuln.Vulnerability.Severity) $severity_level) }}
              <tr class="severity-{{ escapeXML $vuln.Vulnerability.Severity }}">
                <td class="pkg-name">{{ escapeXML $vuln.PkgName }}</td>
                <td>{{ escapeXML $vuln.VulnerabilityID }}</td>
                <td class="severity">{{ escapeXML $vuln.Vulnerability.Severity }}</td>
                <td class="Status">{{ $vuln.Status}}</td>
                <td class="pkg-version">{{ escapeXML $vuln.InstalledVersion }}</td>
                <td>{{ escapeXML $vuln.FixedVersion }}</td>
                <td class="description">{{ escapeXML $vuln.Description }}</td>
                <td class="links" data-more-links="off">
                  {{- range $vuln.Vulnerability.References }}<a href={{ escapeXML . | printf "%q" }}>{{ escapeXML . }}</a>{{- end }}
                </td>
              </tr>
            {{- end }}
          {{- end}}
        {{- end }}
      {{- end }}
      
      {{- if (eq (len .Misconfigurations) 0) }}
        <tr><th colspan="6">No Misconfigurations found</th></tr>
      {{- else }}
        <tr class="sub-header"><th>Type</th><th>Misconf ID</th><th>Check</th><th>Severity</th><th>Message</th></tr>
        {{- range .Misconfigurations }}
          <tr class="severity-{{ escapeXML .Severity }}">
            <td class="misconf-type">{{ escapeXML .Type }}</td>
            <td>{{ escapeXML .ID }}</td>
            <td class="misconf-check">{{ escapeXML .Title }}</td>
            <td class="severity">{{ escapeXML .Severity }}</td>
            <td class="link" data-more-links="off" style="white-space:normal;">
              {{ escapeXML .Message }}<br><a href={{ escapeXML .PrimaryURL | printf "%q" }}>{{ escapeXML .PrimaryURL }}</a></br>
            </td>
          </tr>
        {{- end }}
      {{- end }}
    {{- end }}
    </table>
    {{- else }}
</head>
<body>
    <h1>Trivy Returned Empty Report</h1>
    {{- end }}
</body>
</html>
