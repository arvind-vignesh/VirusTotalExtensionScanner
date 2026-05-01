const MENU_ID = "scan-with-vt";
const RESULT_KEY = "lastScanResult";
const VT_API_BASE = "https://www.virustotal.com/api/v3";
let badgeResetTimeoutId = null;

browser.contextMenus.remove(MENU_ID).catch(() => {});

browser.contextMenus.create({
  id: MENU_ID,
  title: "Scan Link with VirusTotal",
  contexts: ["link"]
});

function encodeUrl(url) {
  return btoa(url)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function scheduleBadgeReset() {
  badgeResetTimeoutId = setTimeout(() => {
    browser.action.setBadgeText({ text: "" }).catch(() => {});
    browser.action.setTitle({ title: "VT Context Scanner" }).catch(() => {});
    badgeResetTimeoutId = null;
  }, 10000);
}

async function updateBadge(result) {
  if (badgeResetTimeoutId !== null) {
    clearTimeout(badgeResetTimeoutId);
    badgeResetTimeoutId = null;
  }

  if (!result || !result.status) {
    await browser.action.setBadgeText({ text: "" });
    await browser.action.setTitle({ title: "VT Context Scanner" });
    return;
  }

  if (result.status === "loading") {
    await browser.action.setBadgeBackgroundColor({ color: "#6b7280" });
    await browser.action.setBadgeText({ text: "..." });
    await browser.action.setTitle({ title: "VirusTotal scan in progress" });
    return;
  }

  if (result.status === "error") {
    await browser.action.setBadgeBackgroundColor({ color: "#b91c1c" });
    await browser.action.setBadgeText({ text: "!" });
    await browser.action.setTitle({ title: result.error || "VirusTotal scan failed" });
    scheduleBadgeReset();
    return;
  }

  const detections = result.malicious ?? 0;
  const suspicious = result.suspicious ?? 0;

  if (detections > 0 || suspicious > 0) {
    await browser.action.setBadgeBackgroundColor({ color: "#b91c1c" });
    await browser.action.setBadgeText({ text: `${detections + suspicious}` });
    await browser.action.setTitle({
      title: `VirusTotal scan finished: ${detections} malicious, ${suspicious} suspicious`
    });
    scheduleBadgeReset();
    return;
  }

  await browser.action.setBadgeBackgroundColor({ color: "#15803d" });
  await browser.action.setBadgeText({ text: "OK" });
  await browser.action.setTitle({ title: "VirusTotal scan finished: no malicious detections" });
  scheduleBadgeReset();
}

async function publishResult(result) {
  await browser.storage.local.set({ [RESULT_KEY]: result });
  await updateBadge(result);
  await browser.runtime.sendMessage({ action: "scanResultUpdated", result }).catch(() => {});
}

async function getUrlReport(apiKey, url) {
  const response = await fetch(`${VT_API_BASE}/urls/${encodeUrl(url)}`, {
    method: "GET",
    headers: {
      "x-apikey": apiKey
    }
  });

  if (!response.ok) {
    const error = new Error(`VirusTotal report request failed with status ${response.status}.`);
    error.status = response.status;
    throw error;
  }

  return response.json();
}

async function submitUrlForScan(apiKey, url) {
  const response = await fetch(`${VT_API_BASE}/urls`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "x-apikey": apiKey
    },
    body: new URLSearchParams({ url })
  });

  if (!response.ok) {
    throw new Error(`VirusTotal scan submission failed with status ${response.status}.`);
  }

  return response.json();
}

async function getAnalysis(apiKey, analysisId) {
  const response = await fetch(`${VT_API_BASE}/analyses/${analysisId}`, {
    method: "GET",
    headers: {
      "x-apikey": apiKey
    }
  });

  if (!response.ok) {
    throw new Error(`VirusTotal analysis request failed with status ${response.status}.`);
  }

  return response.json();
}

async function waitForAnalysisCompletion(apiKey, analysisId) {
  const maxAttempts = 10;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const analysis = await getAnalysis(apiKey, analysisId);
    const status = analysis?.data?.attributes?.status;

    if (status === "completed") {
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, 1500));
  }

  throw new Error("VirusTotal analysis did not complete in time. Please try again.");
}

function mapStatsToResult(url, stats) {
  return {
    status: "done",
    url,
    malicious: stats?.malicious ?? 0,
    suspicious: stats?.suspicious ?? 0,
    harmless: stats?.harmless ?? 0,
    undetected: stats?.undetected ?? 0
  };
}

async function scanUrl(apiKey, url) {
  try {
    const report = await getUrlReport(apiKey, url);
    return mapStatsToResult(url, report?.data?.attributes?.last_analysis_stats);
  } catch (error) {
    if (error.status !== 404) {
      throw error;
    }
  }

  const submission = await submitUrlForScan(apiKey, url);
  await waitForAnalysisCompletion(apiKey, submission?.data?.id);
  const freshReport = await getUrlReport(apiKey, url);
  return mapStatsToResult(url, freshReport?.data?.attributes?.last_analysis_stats);
}

browser.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== MENU_ID || !info.linkUrl) {
    return;
  }

  const url = info.linkUrl;

  await publishResult({
    status: "loading",
    url
  });
  await browser.action.openPopup().catch(() => {});

  const storageResult = await browser.storage.local.get("vtApiKey");
  const apiKey = storageResult.vtApiKey?.trim();

  if (!apiKey) {
    await publishResult({
      status: "error",
      url,
      error: "API key not set. Open the extension settings and add your VirusTotal API key."
    });
    return;
  }

  try {
    const result = await scanUrl(apiKey, url);
    await publishResult(result);
  } catch (error) {
    await publishResult({
      status: "error",
      url,
      error: error.message || "The scan failed. Please try again."
    });
  }
});
