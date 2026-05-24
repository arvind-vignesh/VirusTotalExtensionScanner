const RESULT_KEY = "lastScanResult";
const resultDiv = document.getElementById("result");

function clearResult() {
  while (resultDiv.firstChild) {
    resultDiv.removeChild(resultDiv.firstChild);
  }
}

function appendParagraph(text, className = "") {
  const paragraph = document.createElement("p");
  paragraph.textContent = text;

  if (className) {
    paragraph.className = className;
  }

  resultDiv.appendChild(paragraph);
}

function appendMessage(text, className = "") {
  const message = document.createElement("div");
  message.textContent = text;
  message.className = `message-card ${className}`.trim();
  resultDiv.appendChild(message);
}

function createMetric(label, value, variant) {
  const metric = document.createElement("div");
  metric.className = `metric metric--${variant}`;

  const circle = document.createElement("div");
  circle.className = "metric-circle";
  circle.textContent = String(value);

  const metricLabel = document.createElement("div");
  metricLabel.className = "metric-label";
  metricLabel.textContent = label;

  metric.appendChild(circle);
  metric.appendChild(metricLabel);
  return metric;
}

function renderMetrics(result) {
  const metricsGrid = document.createElement("div");
  metricsGrid.className = "metrics-grid";
  metricsGrid.appendChild(createMetric("Malicious", result.malicious ?? 0, "malicious"));
  metricsGrid.appendChild(createMetric("Suspicious", result.suspicious ?? 0, "suspicious"));
  metricsGrid.appendChild(createMetric("Harmless", result.harmless ?? 0, "harmless"));
  metricsGrid.appendChild(createMetric("Undetected", result.undetected ?? 0, "undetected"));
  resultDiv.appendChild(metricsGrid);
}

function appendReanalyzeButton(url) {
  const button = document.createElement("button");
  button.className = "reanalyze-button";
  button.type = "button";
  button.innerHTML = `
    <svg class="reanalyze-icon" viewBox="0 0 24 24">
      <path d="M19 8l-4 4h3c0 3.31-2.69 6-6 6-1.01 0-1.97-.25-2.8-.7l-1.46 1.46C8.97 19.54 10.43 20 12 20c4.42 0 8-3.58 8-8h3l-4-4zM6 12c0-3.31 2.69-6 6-6 1.01 0 1.97.25 2.8.7l1.46-1.46C15.03 4.46 13.57 4 12 4c-4.42 0-8 3.58-8 8H1l4 4 4-4H6z"/>
    </svg>
    Force Re-analyze
  `;

  button.addEventListener("click", () => {
    renderResult({
      status: "loading",
      url: url
    });

    browser.runtime.sendMessage({
      action: "startScan",
      url: url,
      force: true
    });
  });

  resultDiv.appendChild(button);
}

function renderResult(result) {
  clearResult();

  if (!result) {
    appendParagraph("Right-click a link or enter a URL above to start a scan.", "loading");
    return;
  }

  if (result.status === "loading") {
    appendParagraph(`Scanning: ${result.url}`, "url-text");
    appendMessage("Waiting for VirusTotal...", "loading");
    const loadingCircle = createMetric("Scanning", "...", "undetected");
    loadingCircle.querySelector(".metric-circle").classList.add("loading-circle");
    const loadingWrap = document.createElement("div");
    loadingWrap.className = "metrics-grid";
    loadingWrap.appendChild(loadingCircle);
    resultDiv.appendChild(loadingWrap);
    return;
  }

  if (result.status === "error") {
    appendParagraph(result.url || "Scan error", "url-text");
    appendMessage(result.error || "Something went wrong.");
    if (result.url) {
      appendReanalyzeButton(result.url);
    }
    return;
  }

  appendParagraph(`URL: ${result.url}`, "url-text");
  appendMessage(result.malicious > 0 || result.suspicious > 0 ? "Scan completed with detections." : "Scan completed cleanly.");
  renderMetrics(result);
  appendReanalyzeButton(result.url);
}

browser.runtime.onMessage.addListener((message) => {
  if (message.action === "scanResultUpdated") {
    renderResult(message.result);
  }
});

browser.storage.local.get(RESULT_KEY).then((result) => {
  renderResult(result[RESULT_KEY]);
});

// Form submission handler for manual URL scanning
const scanForm = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");

if (scanForm && urlInput) {
  scanForm.addEventListener("submit", (e) => {
    e.preventDefault();
    let url = urlInput.value.trim();
    if (!url) {
      return;
    }

    // URL Normalization: Automatically prepend https:// if protocol is missing
    if (!/^https?:\/\//i.test(url)) {
      url = "https://" + url;
    }

    // Immediately render loading UI for this URL
    renderResult({
      status: "loading",
      url: url
    });

    // Request the background service to scan this URL
    browser.runtime.sendMessage({
      action: "startScan",
      url: url
    });

    // Blur the input to dismiss active keyboard/focus state
    urlInput.blur();
  });
}

