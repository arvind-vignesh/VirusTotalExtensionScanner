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

function renderResult(result) {
  clearResult();

  if (!result) {
    appendParagraph("Right-click a link to start a scan.", "loading");
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
    return;
  }

  appendParagraph(`URL: ${result.url}`, "url-text");
  appendMessage(result.malicious > 0 || result.suspicious > 0 ? "Scan completed with detections." : "Scan completed cleanly.");
  renderMetrics(result);
}

browser.runtime.onMessage.addListener((message) => {
  if (message.action === "scanResultUpdated") {
    renderResult(message.result);
  }
});

browser.storage.local.get(RESULT_KEY).then((result) => {
  renderResult(result[RESULT_KEY]);
});
