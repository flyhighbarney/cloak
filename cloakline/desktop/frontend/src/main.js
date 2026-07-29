// Wails auto-generates wailsjs/go/main/App.js at build time. In this
// repository we call the bound methods directly through the runtime shim.
// window.go.main.App.<Method>(args...) → Promise<result>.

const prompt = document.getElementById("prompt");
const findingsEmpty = document.getElementById("findings-empty");
const findingsList = document.getElementById("findings-list");
const sendBtn = document.getElementById("send-btn");
const modelSelect = document.getElementById("model");
const responseSection = document.getElementById("response");
const responseText = document.getElementById("response-text");
const settingsBtn = document.getElementById("settings-btn");
const settingsPanel = document.getElementById("settings-panel");
const statusPill = document.getElementById("status-pill");

const KIND_LABEL = {
  ssn: "US Social Security number",
  credit_card: "credit card number",
  email: "email address",
  api_key: "API key",
  aws_key: "AWS access key",
  github_token: "GitHub token",
  private_key: "PEM private key",
};

let debounceTimer = null;

async function refreshFindings() {
  const text = prompt.value;
  if (!text.trim()) {
    findingsEmpty.textContent = "Compose something. It'll be scanned locally.";
    findingsEmpty.classList.remove("hidden");
    findingsList.innerHTML = "";
    return;
  }
  const findings = await window.go.main.App.PreviewRedaction(text);
  if (!findings || findings.length === 0) {
    findingsEmpty.textContent = "No sensitive content detected. Safe to send.";
    findingsEmpty.classList.remove("hidden");
    findingsEmpty.classList.remove("warn");
    findingsList.innerHTML = "";
    return;
  }
  findingsEmpty.classList.add("hidden");
  findingsList.innerHTML = "";
  for (const f of findings) {
    const li = document.createElement("li");
    li.className = "finding";
    li.innerHTML = `<span class="kind">${KIND_LABEL[f.kind] || f.kind}</span> <span class="preview">${f.text}</span>`;
    findingsList.appendChild(li);
  }
}

prompt.addEventListener("input", () => {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(refreshFindings, 200);
});

sendBtn.addEventListener("click", async () => {
  const text = prompt.value.trim();
  if (!text) return;
  sendBtn.disabled = true;
  sendBtn.textContent = "Sending…";
  const result = await window.go.main.App.SendPrompt(modelSelect.value, text);
  sendBtn.disabled = false;
  sendBtn.textContent = "Send to AI";
  if (result.error) {
    responseText.innerHTML = `<div class="error">Error: ${escapeHTML(result.error)}${
      result.detail ? "<br><small>" + escapeHTML(result.detail) + "</small>" : ""
    }</div>`;
  } else {
    responseText.textContent = result.reply;
  }
  responseSection.classList.remove("hidden");
});

settingsBtn.addEventListener("click", async () => {
  const cfg = await window.go.main.App.GetConfig();
  document.getElementById("cfg-gateway").value = cfg.gateway || "";
  document.getElementById("cfg-tenant").value = cfg.tenant || "";
  document.getElementById("cfg-key").value = "";
  settingsPanel.classList.remove("hidden");
});

document.getElementById("cfg-cancel").addEventListener("click", () => {
  settingsPanel.classList.add("hidden");
});

document.getElementById("cfg-save").addEventListener("click", async () => {
  const gateway = document.getElementById("cfg-gateway").value.trim();
  const apiKey = document.getElementById("cfg-key").value.trim();
  const tenant = document.getElementById("cfg-tenant").value.trim();
  const result = await window.go.main.App.SaveConfig(gateway, apiKey, tenant);
  if (result === "ok") {
    settingsPanel.classList.add("hidden");
    checkHealth();
  } else {
    alert(result);
  }
});

async function checkHealth() {
  const ok = await window.go.main.App.HealthCheck();
  statusPill.textContent = ok ? "connected" : "not connected";
  statusPill.className = "pill " + (ok ? "ok" : "err");
}

function escapeHTML(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Initial state.
refreshFindings();
checkHealth();
setInterval(checkHealth, 30_000);
