const state = {
  view: "dashboard",
  credentials: [],
  notifications: [],
  recommendations: [],
  audit: [],
  analytics: null,
  analyticsPlots: null,
  filters: {
    search: "",
    risk: "All",
  },
  selectedId: null,
  notificationFilter: "All",
};

const riskColors = {
  Low: "#15803d",
  Medium: "#b45309",
  High: "#ea580c",
  Critical: "#b91c1c",
  Expired: "#b91c1c",
  "0-7 days": "#ea580c",
  "8-15 days": "#b45309",
  "16-30 days": "#0e7490",
  "31+ days": "#15803d",
  "MFA enabled": "#15803d",
  "Successful rotations": "#15803d",
  "Password strength": "#15803d",
  "Expired password": "#b91c1c",
  "Failed rotations": "#b91c1c",
  "Expiry window": "#ea580c",
  "No MFA": "#ea580c",
  "Reminders ignored": "#ea580c",
  "Slow response time": "#b45309",
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function queryString() {
  const params = new URLSearchParams();
  Object.entries(state.filters).forEach(([key, value]) => {
    if (value && value !== "All") params.set(key, value);
  });
  return params.toString();
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

let isRefreshing = false;
async function refreshAll() {
  if (isRefreshing) return;
  isRefreshing = true;
  try {
    const qs = queryString();
    const [summary, credentials, recommendations, notifications, audit, analytics, analyticsPlotsRaw] = await Promise.all([
      api(`/api/summary?${qs}`),
      api(`/api/credentials?${qs}`),
      api(`/api/recommendations?${qs}`),
      api("/api/notifications"),
      api("/api/audit"),
      api(`/api/analytics?${qs}`),
      api(`/api/analytics/plots`).catch(() => null),
    ]);
    state.summary = summary;
    state.credentials = credentials;
    state.recommendations = recommendations;
    state.notifications = notifications;
    state.audit = audit;
    state.analytics = analytics;
    state.analyticsPlots = typeof analyticsPlotsRaw === 'string' ? JSON.parse(analyticsPlotsRaw) : analyticsPlotsRaw;
    if (!state.selectedId && credentials.length) state.selectedId = credentials[0].id;
    if (!credentials.some((item) => item.id === state.selectedId) && credentials.length) {
      state.selectedId = credentials[0].id;
    }
    render();
  } finally {
    isRefreshing = false;
  }
}

function selectedCredential() {
  return state.credentials.find((item) => item.id === state.selectedId) || state.credentials[0];
}

function riskPill(risk) {
  return `<span class="pill risk-${escapeHtml(risk)}">${escapeHtml(risk)}</span>`;
}

function formatPostureData(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  const order = ["Critical", "High", "Medium", "Low"];
  const keys = Object.keys(data);
  const orderedKeys = order.filter((k) => keys.includes(k)).concat(keys.filter((k) => !order.includes(k)));
  return orderedKeys.map((label) => ({ label, value: Number(data[label]) || 0 }));
}

function render() {
  renderMetrics();
  const postureData = formatPostureData(
    state.summary?.credential_posture || state.summary?.risk_distribution || state.analytics?.credential_posture
  );
  renderBars("#riskBars", postureData);
  renderExpiryList();
  renderCredentialRows();
  renderExplorerRows();
  renderDetailPanel();
  renderRecommendations();
  renderNotifications();
  renderAudit();
  renderAnalytics();
  if (state.summary?.model_version) {
    $("#modelVersion").textContent = state.summary.model_version;
  }
}

function renderMetrics() {
  const metrics = [
    ["Total Accounts", state.summary.total, "monitored metadata records"],
    ["Expiring Soon", state.summary.expiring, "inside seven-day alert window"],
    ["Critical Risk", state.summary.critical, "requires urgent ownership"],
    ["Expired", state.summary.expired, "access outage risk"],
  ];
  $("#metricGrid").innerHTML = metrics
    .map(([label, value, hint]) => `
      <article class="metric">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
        <small>${escapeHtml(hint)}</small>
      </article>
    `)
    .join("");
}

function renderBars(selector, rows) {
  const el = typeof selector === "string" ? $(selector) : selector;
  if (!el) return;
  if (!rows || !Array.isArray(rows) || rows.length === 0) {
    el.innerHTML = '<p class="muted" style="padding: 8px 0;">No data available</p>';
    return;
  }

  // Calculate dynamic maximum based on absolute values to support both positive and negative weights
  const max = Math.max(1, ...rows.map((row) => Math.abs(Number(row.value) || 0)));

  el.innerHTML = rows
    .map((row) => {
      const rawVal = Number(row.value) || 0;
      const absVal = Math.abs(rawVal);
      // Zero values should have 0% width; non-zero values scaled proportionally (minimum 3% for visibility)
      const width = rawVal === 0 ? 0 : Math.min(100, Math.max(3, (absVal / max) * 100));

      let color = riskColors[row.label];
      if (!color) {
        color = rawVal < 0 ? "#15803d" : "#0e7490";
      }

      const displayVal = Number.isInteger(rawVal) ? rawVal : rawVal.toFixed(2);

      return `
        <div class="bar-row">
          <span class="bar-label" title="${escapeHtml(row.label)}">${escapeHtml(row.label)}</span>
          <span class="bar-track"><span class="bar-fill" style="width:${width}%;background:${color}"></span></span>
          <span class="bar-value">${escapeHtml(displayVal)}</span>
        </div>
      `;
    })
    .join("");
}

function renderExpiryList() {
  const items = [...state.credentials]
    .sort((a, b) => a.days_to_expiry - b.days_to_expiry)
    .slice(0, 5);
  $("#expiryList").innerHTML = items
    .map((item) => `
      <button class="expiry-item ${item.id === state.selectedId ? "selected" : ""}" data-select="${item.id}">
        <span>
          <strong>${escapeHtml(item.database_name)}</strong>
          <span class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.owner)}</span>
        </span>
        ${riskPill(item.risk)}
        <span class="${item.days_to_expiry < 0 ? "danger-text" : "muted"}">
          ${escapeHtml(expiryText(item.days_to_expiry))}
        </span>
      </button>
    `)
    .join("");
}

function expiryText(days) {
  if (days < 0) return `${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} overdue`;
  if (days === 0) return "expires today";
  return `${days} days left`;
}

function renderCredentialRows() {
  $("#credentialRows").innerHTML = state.credentials
    .map((item) => credentialTableRow(item, ["name", "risk", "expiry", "action"]))
    .join("");
}

function renderExplorerRows() {
  $("#explorerRows").innerHTML = state.credentials
    .map((item) => credentialTableRow(item, ["database", "username", "owner", "expiry_action"]))
    .join("");
}

function credentialTableRow(item, columns) {
  const cells = {
    name: `
      <td>
        <div class="credential-name">
          <strong>${escapeHtml(item.database_name)}</strong>
          <span class="muted">${escapeHtml(item.username)}</span>
        </div>
      </td>`,
    database: `<td>${escapeHtml(item.database_name)}</td>`,
    username: `<td>${escapeHtml(item.username)}</td>`,
    owner: `<td>${escapeHtml(item.owner)}</td>`,
    risk: `<td>${riskPill(item.risk)} <span class="muted">${Math.round(item.risk_probability * 100)}%</span></td>`,
    expiry: `<td class="${item.days_to_expiry < 0 ? "danger-text" : ""}">${escapeHtml(expiryText(item.days_to_expiry))}</td>`,
    action: `<td>${escapeHtml(item.recommendation.action)}</td>`,
    expiry_action: `<td style="display: flex; align-items: center; justify-content: space-between;">
      <span class="${item.days_to_expiry < 0 ? "danger-text" : ""}">${escapeHtml(expiryText(item.days_to_expiry))}</span>
      <button class="small-button ghost-button" style="padding: 2px 6px;" data-edit-expiry="${item.id}">✏️ Edit</button>
    </td>`,
  };
  return `<tr data-select="${item.id}" class="${item.id === state.selectedId ? "selected" : ""}">${columns.map((key) => cells[key]).join("")}</tr>`;
}

function renderDetailPanel() {
  const item = selectedCredential();
  if (!item) {
    $("#detailPanel").innerHTML = "<p>No credential selected.</p>";
    return;
  }
  const timelineWidth = Math.max(3, Math.min(100, ((90 - Math.max(0, item.days_to_expiry)) / 90) * 100));
  $("#detailPanel").innerHTML = `
    <p class="eyebrow">Credential details</p>
    <h2>${escapeHtml(item.database_name)}</h2>
    <p class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.secret_ref)}</p>
    <div class="detail-grid">
      <div class="detail-stat"><span>Risk</span><strong>${riskPill(item.risk)} ${Math.round(item.risk_probability * 100)}%</strong></div>
      <div class="detail-stat"><span>Expiry</span><strong>${escapeHtml(expiryText(item.days_to_expiry))}</strong></div>
      <div class="detail-stat"><span>Owner</span><strong>${escapeHtml(item.owner)}</strong></div>
    </div>
    <div class="timeline" title="Credential age vs expiry cycle"><span style="width:${timelineWidth}%"></span></div>
    <p class="muted">Expiry timeline: ${escapeHtml(item.credential_age)} days old, expires ${escapeHtml(item.expiry_date)}.</p>
    <h3>${escapeHtml(item.recommendation.action)}</h3>
    <p>${escapeHtml(item.recommendation.explanation)}</p>
    <div class="stakeholders">${item.recommendation.stakeholders.map((name) => `<span>${escapeHtml(name)}</span>`).join("")}</div>
    <div class="factor-list">
      ${item.risk_factors
        .map((factor) => `
          <div class="factor">
            <span><strong>${escapeHtml(factor.label)}</strong><br><span class="muted">${escapeHtml(factor.evidence)}</span></span>
            <span class="muted">${Math.round(factor.weight * 100)} pts</span>
          </div>
        `)
        .join("")}
    </div>
  `;
}

function renderRecommendations() {
  $("#recommendationList").innerHTML = state.recommendations
    .map(function (item) {
      var factors = (item.top_factors || []).slice(0, 5);
      var factorBarsHtml = "";
      if (factors.length) {
        factorBarsHtml = '<div class="factor-bars">';
        for (var i = 0; i < factors.length; i++) {
          var f = factors[i];
          var absWeight = Math.min(Math.abs(f.weight) * 100, 100);
          var cls = f.weight >= 0 ? "positive" : "negative";
          factorBarsHtml += '<div class="factor-bar">' +
            '<span class="factor-label">' + escapeHtml(f.label) + '</span>' +
            '<span class="factor-track"><span class="factor-fill ' + cls + '" style="width:' + absWeight + '%"></span></span>' +
            '<span class="factor-evidence">' + escapeHtml(f.evidence) + '</span>' +
            '</div>';
        }
        factorBarsHtml += '</div>';
      }

      var badgesHtml = '<div class="rec-badges">';
      if (item.approval_required) {
        badgesHtml += '<span class="approval-badge">\u26A0 Approval Required</span>';
      }
      if (item.uses_mfa) {
        badgesHtml += '<span class="mfa-badge mfa-on">\uD83D\uDD12 MFA On</span>';
      } else {
        badgesHtml += '<span class="mfa-badge mfa-off">\u26A0 No MFA</span>';
      }
      badgesHtml += '</div>';

      var stakeholdersHtml = item.stakeholders.map(function(name) {
        return '<span>' + escapeHtml(name) + '</span>';
      }).join("");

      return '<article class="recommendation-item">' +
        '<div class="rec-topline">' +
          '<div>' +
            '<p class="eyebrow">' + escapeHtml(item.urgency) + ' urgency</p>' +
            '<h2>' + escapeHtml(item.database_name) + '</h2>' +
            '<p class="muted">' + escapeHtml(item.username) + ' - ' + escapeHtml(expiryText(item.days_to_expiry)) + '</p>' +
          '</div>' +
          riskPill(item.risk) +
        '</div>' +
        '<h3>' + escapeHtml(item.action) + '</h3>' +
        '<p>' + escapeHtml(item.explanation) + '</p>' +
        factorBarsHtml +
        badgesHtml +
        '<div class="stakeholders">' + stakeholdersHtml + '</div>' +
      '</article>';
    })
    .join("");
}

function renderNotifications() {
  const search = state.filters.search.trim().toLowerCase();

  const filtered = state.notifications.filter(item => {
    const matchesStatus =
      state.notificationFilter === "All" ||
      item.notification_status === state.notificationFilter;

    const matchesSearch =
      !search ||
      String(item.database_name || "").toLowerCase().includes(search) ||
      String(item.username || "").toLowerCase().includes(search) ||
      String(item.owner || "").toLowerCase().includes(search) ||
      String(item.recipient_email || item.email || "").toLowerCase().includes(search) ||
      String(item.notification_status || "").toLowerCase().includes(search);

    return matchesStatus && matchesSearch;
  });


  $("#notificationList").innerHTML = filtered
    .map((item) => {
      const status = item.notification_status;
      const days = item.days_to_expiry;
      const daysText = days < 0 ? `${Math.abs(days)}d overdue` : days === 0 ? "Today" : `${days} days`;
      const daysClass = days <= 3 ? "danger-text" : days <= 7 ? "warning-text" : "";

      let statusClass = "env";
      if (status === "Escalated") statusClass = "risk-Critical";
      else if (status === "Sent") statusClass = "risk-High";
      else if (status === "Reminded") statusClass = "risk-Low";
      else if (status === "No Alerts") statusClass = "env";

      let actions = "";
      const recipientEmail = item.recipient_email || item.email || "";
      if (status === "Sent" && item.notification_id && recipientEmail) {
        actions = `<button class="small-button" data-ack="${item.notification_id}">Acknowledge</button> <button class="small-button ghost-button" style="margin-left: 8px; border: 1px solid var(--border);" data-remind="${item.notification_id}">Send Reminder</button>`;
      } else if (status === "Sent" && item.notification_id) {
        actions = `<button class="small-button" data-ack="${item.notification_id}">Acknowledge</button> <button class="small-button ghost-button" style="margin-left: 8px; border: 1px solid var(--border);" data-add-email="${item.id}">Add Email</button>`;
      } else if (status === "No Alerts") {
        actions = `<span class="muted" style="color: #10b981;">✓ Secure</span> <button class="small-button ghost-button" style="margin-left: 8px; font-size: 0.8em; padding: 2px 6px;" data-test-alert="${item.id}">Test Alert</button>`;
      } else if (item.notification_id) {
        actions = `<span class="muted">${escapeHtml(status)}</span> <button class="small-button ghost-button" style="margin-left: 8px; font-size: 0.8em; padding: 2px 6px;" data-undo="${item.notification_id}">Undo</button>`;
      } else {
        actions = `<span class="muted">${escapeHtml(status)}</span>`;
      }

      const isEscalated = status === "Escalated";

      return `
      <tr class="${isEscalated ? "danger-text" : ""}" style="${isEscalated ? "background: #fef2f2;" : ""}">
        <td>
          <div class="credential-name">
            <strong>${escapeHtml(item.database_name)}</strong>
            <span class="muted">${escapeHtml(item.username)}</span>
          </div>
        </td>
        <td>
          <strong>${escapeHtml(item.owner)}</strong>
          <span class="muted" style="display:block;">${escapeHtml(recipientEmail || "No email on file")}</span>
        </td>
        <td class="${daysClass}"><strong>${daysText}</strong></td>
        <td><span class="pill ${statusClass}">${escapeHtml(status)}</span></td>
        <td>${actions}</td>
      </tr>
      `;
    })
    .join("");
}

function renderAudit() {
 const search = state.filters.search.trim().toLowerCase();

  const filtered = state.audit.filter(item =>
    !search ||
    String(item.action || "").toLowerCase().includes(search) ||
    String(item.actor || "").toLowerCase().includes(search) ||
    String(item.entity || "").toLowerCase().includes(search) ||
    String(item.entity_id || "").toLowerCase().includes(search) ||
    String(item.details || "").toLowerCase().includes(search) ||
    String(item.created_at || "").toLowerCase().includes(search)
  );

  $("#auditList").innerHTML = filtered
    .map((item) => `
      <article class="audit-item">
        <div class="audit-topline">
          <strong>${escapeHtml(item.action)}</strong>
          <span class="muted">${escapeHtml(item.created_at)}</span>
        </div>
        <span class="muted">${escapeHtml(item.actor)} - ${escapeHtml(item.entity)} #${escapeHtml(item.entity_id)}</span>
        <p>${escapeHtml(item.details)}</p>
      </article>
    `)
    .join("");
}

function renderPlot(containerId, plotData, emptyMessage) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const hasData = plotData && Array.isArray(plotData.data) && plotData.data.length > 0 && plotData.data.some(trace => {
    if (!trace) return false;
    if (trace.type === "pie") {
      return Array.isArray(trace.values) && trace.values.length > 0 && trace.values.some(v => Number(v) > 0);
    }
    if (Array.isArray(trace.y) && trace.y.length > 0) return true;
    if (Array.isArray(trace.x) && trace.x.length > 0) return true;
    if (Array.isArray(trace.values) && trace.values.length > 0) return true;
    return false;
  });

  if (!hasData) {
    if (typeof Plotly !== "undefined") {
      try { Plotly.purge(container); } catch (e) {}
    }
    container.innerHTML = `<div class="chart-empty-message" style="display: flex; align-items: center; justify-content: center; height: 100%; min-height: 220px; color: var(--muted, #64748b); font-size: 0.95rem; text-align: center; padding: 24px;">${escapeHtml(emptyMessage || "No data available")}</div>`;
    return;
  }

  const msg = container.querySelector(".chart-empty-message");
  if (msg) container.innerHTML = "";

  const config = { responsive: true, displayModeBar: false };
  const layout = {
    ...plotData.layout,
    autosize: true,
    margin: plotData.layout?.margin || { l: 20, r: 20, t: 20, b: 20 },
  };

  try {
    Plotly.react(containerId, plotData.data, layout, config);
  } catch (err) {
    console.error(`Error rendering chart ${containerId}:`, err);
  }
}

function renderAnalytics() {
  if (state.analytics) {
    const expiryBuckets = state.analytics.expiry_buckets || state.analytics.expiryBuckets || [];
    const topFactors = state.analytics.top_factors || state.analytics.topFactors || state.analytics.risk_factors || state.analytics.riskFactors || [];
    renderBars("#expiryBuckets", expiryBuckets);
    renderBars("#factorBars", topFactors);
  }

  if (state.analyticsPlots && typeof Plotly !== "undefined") {
    console.log("Rotation Status Data:", state.analyticsPlots.rotation_status);
    console.log("Verification Status Data:", state.analyticsPlots.verification_status);
    console.log("Rotation vs Verification Data:", state.analyticsPlots.rotation_vs_verification);
    console.log("Expiry Timeline Data:", state.analyticsPlots.expiry_timeline);
    console.log("Audit Activity Data:", state.analyticsPlots.audit_activity);

    renderPlot("plot-credentials-by-role", state.analyticsPlots.credentials_by_role, "No role data available");
    renderPlot("plot-credentials-by-department", state.analyticsPlots.credentials_by_department, "No department data available");
    renderPlot("plot-expiry-timeline", state.analyticsPlots.expiry_timeline, "No expiry timeline data available");
    renderPlot("plot-action-distribution", state.analyticsPlots.action_distribution, "No action distribution data available");
    renderPlot("plot-audit-activity", state.analyticsPlots.audit_activity, "No audit activity data available");
    renderPlot("plot-rotation-status", state.analyticsPlots.rotation_status, "No rotation data available");
    renderPlot("plot-verification-status", state.analyticsPlots.verification_status, "No verification data available");
    renderPlot("plot-rotation-vs-verification", state.analyticsPlots.rotation_vs_verification, "No rotation vs verification data available");
  }
}

function setView(view) {
  state.view = view;
  $$(".view").forEach((section) => section.classList.toggle("active", section.id === view));
  $$(".nav-tabs button").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  if (view === "analytics") {
    renderAnalytics();
    if (typeof Plotly !== "undefined") {
      setTimeout(() => {
        $$(".plotly-container").forEach((el) => {
          if (el.children.length > 0 && !el.querySelector(".chart-empty-message")) {
            try { Plotly.Plots.resize(el); } catch (e) {}
          }
        });
      }, 100);
    }
  }
}

function bindEvents() {
  $$(".nav-tabs button").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
  $("#searchInput").addEventListener("input", (event) => {
    state.filters.search = event.target.value;
    debounceRefresh();
  });
  $("#riskFilter").addEventListener("change", (event) => {
    state.filters.risk = event.target.value;
    refreshAll();
  });
  document.body.addEventListener("click", async (event) => {
    const editExpiryTarget = event.target.closest("[data-edit-expiry]");
    if (editExpiryTarget) {
      event.stopPropagation(); // prevent row selection
      const credId = editExpiryTarget.dataset.editExpiry;
      const cred = state.credentials.find(c => String(c.id) === credId);
      if (!cred) return;
      const newDays = prompt(`Enter new days to expiry for ${cred.database_name} (${cred.owner}):`, cred.days_to_expiry);
      if (newDays !== null) {
        const parsedDays = parseInt(newDays, 10);
        if (!isNaN(parsedDays)) {
          await api(`/api/credentials/${credId}/expiry`, {
            method: "PUT",
            body: JSON.stringify({ days: parsedDays, actor: "demo-admin" })
          });
          showToast("Success", "Expiry updated globally.");
          await refreshAll();
        } else {
          showToast("Error", "Invalid number entered.");
        }
      }
      return;
    }
    if (event.target.matches("#notificationFilters button")) {
      const filter = event.target.dataset.filter;
      state.notificationFilter = filter;
      $$("#notificationFilters button").forEach(btn => btn.className = "small-button ghost-button");
      event.target.className = "active small-button";
      renderNotifications();
      return;
    }
    const selectTarget = event.target.closest("[data-select]");
    if (selectTarget) {
      state.selectedId = Number(selectTarget.dataset.select);
      render();
      if (selectTarget.dataset.viewTarget) setView(selectTarget.dataset.viewTarget);
    }
    const ackTarget = event.target.closest("[data-ack]");
    if (ackTarget) {
      await api(`/api/notifications/${ackTarget.dataset.ack}/ack`, {
        method: "POST",
        body: JSON.stringify({ actor: "demo-admin" }),
      });
      showToast("Acknowledged", "Notification has been acknowledged and audited.");
      await refreshAll();
    }
    const remindTarget = event.target.closest("[data-remind]");
    if (remindTarget) {
      try {
        const res = await api(`/api/notifications/${remindTarget.dataset.remind}/remind`, {
          method: "POST",
          body: JSON.stringify({ actor: "demo-admin" }),
        });
        if (res && res.mailto && res.mailto.to) {
          const m = res.mailto;
          const gmailUrl = `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(m.to)}&su=${encodeURIComponent(m.subject)}&body=${encodeURIComponent(m.body)}`;
          window.open(gmailUrl, '_blank');

          // Extract the magic link to make it clickable on the dashboard
          const magicLinkMatch = m.body.match(/(http:\/\/[^\s]+reset\/[a-zA-Z0-9_-]+)/);
          if (magicLinkMatch) {
            showToast("Reminder Drafted", `Gmail opened in a new tab.<br><br><b>For testing:</b> <a href="${magicLinkMatch[1]}" target="_blank" style="color: #60a5fa; text-decoration: underline;">Click here to open the Magic Link</a> directly.`, true, 10000);
          } else {
            showToast("Gmail Opened", "A new tab has been opened with your drafted message.");
          }
        } else {
          showToast("Recipient Missing", "No owner email is saved for this credential.");
        }
        await refreshAll();
      } catch (err) {
        showToast("Reminder Blocked", err.message || "Unable to prepare the reminder email.");
      }
    }
    const addEmailTarget = event.target.closest("[data-add-email]");
    if (addEmailTarget) {
      const email = window.prompt("Owner email address");
      if (!email) return;
      try {
        await api(`/api/credentials/${addEmailTarget.dataset.addEmail}/email`, {
          method: "PUT",
          body: JSON.stringify({ email, actor: "demo-admin" }),
        });
        showToast("Email Saved", "Reminder recipient updated for this credential.");
        await refreshAll();
      } catch (err) {
        showToast("Email Not Saved", err.message || "Please enter a valid email address.");
      }
    }
    const undoTarget = event.target.closest("[data-undo]");
    if (undoTarget) {
      await api(`/api/notifications/${undoTarget.dataset.undo}/undo`, { method: "POST" });
      showToast("Undone", "Notification status reverted to Sent.");
      await refreshAll();
    }
    const testAlertTarget = event.target.closest("[data-test-alert]");
    if (testAlertTarget) {
      await api(`/api/credentials/${testAlertTarget.dataset.testAlert}/test-alert`, { method: "POST" });
      showToast("Alert Generated", "A test notification has been created for this credential.");
      await refreshAll();
    }
  });
  $("#resetDemo").addEventListener("click", async () => {
    await api("/api/demo/reset", { method: "POST", body: "{}" });
    state.selectedId = null;
    await refreshAll();
  });
}

let refreshTimer = null;
function debounceRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refreshAll, 250);
}

function showToast(title, message, isHtml = false, duration = 4000) {
  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    document.body.appendChild(container);
  }
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `<h4>${escapeHtml(title)}</h4><p style="margin-top: 4px;">${isHtml ? message : escapeHtml(message)}</p>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("hiding");
    toast.addEventListener("animationend", () => toast.remove());
  }, duration);
}

// Handle initial view if requested via URL path or hash
if (window.location.pathname === "/analytics" || window.location.hash === "#analytics") {
  state.view = "analytics";
  setView("analytics");
}

bindEvents();
refreshAll().catch((error) => {
  document.body.innerHTML = `<main class="workspace"><section class="panel"><h1>SecureRotate could not load</h1><p>${escapeHtml(error.message)}</p></section></main>`;
});

// Handle responsive Plotly chart resizing on window resize
window.addEventListener("resize", () => {
  if (state.view === "analytics" && typeof Plotly !== "undefined") {
    $$(".plotly-container").forEach((el) => {
      if (el.children.length > 0 && !el.querySelector(".chart-empty-message")) {
        try { Plotly.Plots.resize(el); } catch (e) {}
      }
    });
  }
});

// Auto-polling for live updates every 10 seconds
setInterval(() => {
  if (document.visibilityState === "visible") refreshAll();
}, 10000);
