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

function renderResult(result) {
  clearResult();

  if (!result) {
    appendParagraph("Right-click a link to start a scan.", "loading");
    return;
  }

  if (result.status === "loading") {
    appendParagraph(`Scanning: ${result.url}`, "url-text");
    appendParagraph("Waiting for VirusTotal...", "loading");
    return;
  }

  if (result.status === "error") {
    appendParagraph(result.url || "Scan error", "url-text");
    appendParagraph(result.error || "Something went wrong.", "danger");
    return;
  }

  const isDanger = result.malicious > 0;
  appendParagraph(`URL: ${result.url}`, "url-text");
  appendParagraph(`Status: ${isDanger ? "DANGER!" : "SAFE"}`, isDanger ? "danger" : "safe");
  appendParagraph(`Malicious: ${result.malicious} | Suspicious: ${result.suspicious}`);
  appendParagraph(`Harmless: ${result.harmless} | Undetected: ${result.undetected}`);
}

browser.runtime.onMessage.addListener((message) => {
  if (message.action === "scanResultUpdated") {
    renderResult(message.result);
  }
});

browser.storage.local.get(RESULT_KEY).then((result) => {
  renderResult(result[RESULT_KEY]);
});
