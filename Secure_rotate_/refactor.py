import re

# app.js
with open("c:/Users/cheta/Desktop/cts14/public/app.js", "r") as f:
    app_js = f.read()

app_js = app_js.replace('environment: "All",\n    risk: "All",\n    account_type: "All",', 'risk: "All",')
app_js = app_js.replace('Critical: "#b91c1c",\n  Production: "#0e7490",\n  Staging: "#6d28d9",\n  Development: "#15803d",\n  Expired: "#b91c1c",', 'Critical: "#b91c1c",\n  Expired: "#b91c1c",')
app_js = app_js.replace('function environmentPill(environment) {\n  return `<span class="pill env">${escapeHtml(environment)}</span>`;\n}\n\nfunction render() {', 'function render() {')
app_js = app_js.replace('.map((item) => credentialTableRow(item, ["name", "environment", "risk", "expiry", "action"]))', '.map((item) => credentialTableRow(item, ["name", "risk", "expiry", "action"]))')
app_js = app_js.replace('.map((item) => credentialTableRow(item, ["database", "username", "owner", "privilege", "dependencies", "risk", "action"]))', '.map((item) => credentialTableRow(item, ["database", "username", "owner", "risk", "action"]))')
app_js = app_js.replace('''    name: `
      <td>
        <div class="credential-name">
          <strong>${escapeHtml(item.database_name)}</strong>
          <span class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.account_type)}</span>
        </div>
      </td>`,
    database: `<td>${escapeHtml(item.database_name)}</td>`,
    username: `<td>${escapeHtml(item.username)}</td>`,
    owner: `<td>${escapeHtml(item.owner)}</td>`,
    privilege: `<td>${escapeHtml(item.privilege_level)}</td>`,
    dependencies: `<td>${escapeHtml(item.dependency_count)}</td>`,
    environment: `<td>${environmentPill(item.environment)}</td>`,
    risk:''', '''    name: `
      <td>
        <div class="credential-name">
          <strong>${escapeHtml(item.database_name)}</strong>
          <span class="muted">${escapeHtml(item.username)}</span>
        </div>
      </td>`,
    database: `<td>${escapeHtml(item.database_name)}</td>`,
    username: `<td>${escapeHtml(item.username)}</td>`,
    owner: `<td>${escapeHtml(item.owner)}</td>`,
    risk:''')
app_js = app_js.replace('''      <div class="detail-stat"><span>Risk</span><strong>${riskPill(item.risk)} ${Math.round(item.risk_probability * 100)}%</strong></div>
      <div class="detail-stat"><span>Expiry</span><strong>${escapeHtml(expiryText(item.days_to_expiry))}</strong></div>
      <div class="detail-stat"><span>Privilege</span><strong>${escapeHtml(item.privilege_level)}</strong></div>
      <div class="detail-stat"><span>Dependencies</span><strong>${escapeHtml(item.dependency_count)} apps/services</strong></div>
      <div class="detail-stat"><span>Owner</span><strong>${escapeHtml(item.owner)}</strong></div>
      <div class="detail-stat"><span>DBA</span><strong>${escapeHtml(item.dba)}</strong></div>''', '''      <div class="detail-stat"><span>Risk</span><strong>${riskPill(item.risk)} ${Math.round(item.risk_probability * 100)}%</strong></div>
      <div class="detail-stat"><span>Expiry</span><strong>${escapeHtml(expiryText(item.days_to_expiry))}</strong></div>
      <div class="detail-stat"><span>Owner</span><strong>${escapeHtml(item.owner)}</strong></div>''')
app_js = app_js.replace('''    <h2>${escapeHtml(item.database_name)}</h2>
    <p class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.environment)} - ${escapeHtml(item.account_type)}</p>
    <div class="detail-grid">''', '''    <h2>${escapeHtml(item.database_name)}</h2>
    <p class="muted">${escapeHtml(item.username)}</p>
    <div class="detail-grid">''')
app_js = app_js.replace('''  $("#envFilter").addEventListener("change", (event) => {
    state.filters.environment = event.target.value;
    refreshAll();
  });
  $("#riskFilter").addEventListener("change", (event) => {
    state.filters.risk = event.target.value;
    refreshAll();
  });
  $("#typeFilter").addEventListener("change", (event) => {
    state.filters.account_type = event.target.value;
    refreshAll();
  });''', '''  $("#riskFilter").addEventListener("change", (event) => {
    state.filters.risk = event.target.value;
    refreshAll();
  });''')

with open("c:/Users/cheta/Desktop/cts14/public/app.js", "w") as f:
    f.write(app_js)

# index.html
with open("c:/Users/cheta/Desktop/cts14/public/index.html", "r") as f:
    index_html = f.read()

index_html = re.sub(r'<label>\s*<span>Environment</span>\s*<select id="envFilter">.*?</select>\s*</label>', '', index_html, flags=re.DOTALL)
index_html = re.sub(r'<label>\s*<span>Account Type</span>\s*<select id="typeFilter">.*?</select>\s*</label>', '', index_html, flags=re.DOTALL)
index_html = index_html.replace('<th>Environment</th>\n              <th>Risk Score</th>', '<th>Risk Score</th>')
index_html = index_html.replace('<th>Privilege</th>\n              <th>Dependencies</th>\n              <th>Risk</th>', '<th>Risk</th>')
index_html = index_html.replace('<a href="/user">User Portal</a>', '')

with open("c:/Users/cheta/Desktop/cts14/public/index.html", "w") as f:
    f.write(index_html)

# login.html
with open("c:/Users/cheta/Desktop/cts14/public/login.html", "r") as f:
    login_html = f.read()

payload_regex = r'const payload = \{\s*database_name: database,\s*username: email,\s*password: password,\s*owner: name,\s*app_owner: name,\s*expiry_date: expiryString,\s*account_type: "Service",\s*environment: "Production",\s*privilege_level: "Read",\s*dependency_count: 1,\s*criticality: 3,\s*usage_frequency: 100\s*\};'
new_payload = '''const payload = {
                        database_name: database,
                        username: email,
                        password: password,
                        owner: name,
                        expiry_date: expiryString
                    };'''
login_html = re.sub(payload_regex, new_payload, login_html)
with open("c:/Users/cheta/Desktop/cts14/public/login.html", "w") as f:
    f.write(login_html)
