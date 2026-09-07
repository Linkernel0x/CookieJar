browser.runtime.onInstalled.addListener(async () => {
    console.log("[CookieJar] Extension Installed/Updated!");
    try {
        const storage = await browser.storage.local.get("CookieJar");
        if (storage.CookieJar) {
            console.log("[CookieJar] Existing profile found. Retaining data.");
        } else {
            const initialProfile = new Profile();
            await browser.storage.local.set({ CookieJar: initialProfile.toJSON() });
            console.log("[CookieJar] Initialized new profile.");
        }
    } catch (error) {
        console.error("[CookieJar] Error initializing storage:", error);
    }
});

browser.downloads.onCreated.addListener(async (downloadItem) => {
    try {
        const storage = await browser.storage.local.get("CookieJar");
        const settings = storage.CookieJar?.settings?.virustotal || {};

        if (!settings.downloadScan?.enabled) return;

        const apiKey = getVTApiKey(settings, "downloadScan");
        if (!apiKey) return;

        const isSafe = await checkDownloadUrlSafety(downloadItem.url, apiKey);
        const minResults = settings.downloadScan?.minimumResults || 1;

        if (isSafe !== null && isSafe >= minResults) {
            await browser.downloads.cancel(downloadItem.id);
            await browser.downloads.erase({ id: downloadItem.id });

            sendNotification("CookieJar - Download Blocked", `Malicious file detected: ${downloadItem.filename}`);
        }
    } catch (error) {
        console.error("[CookieJar] Error while handling download:", error);
    }
});

async function checkDownloadUrlSafety(downloadUrl, apiKey) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(downloadUrl);
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashBase64 = btoa(String.fromCharCode(...hashArray));
        const urlId = hashBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            method: "GET",
            headers: { "x-apikey": apiKey }
        });

        if (!response.ok) return null;

        const result = await response.json();
        return result.data?.attributes?.last_analysis_stats?.malicious || 0;
    } catch {
        return null;
    }
}

async function getVTApiKey(vtSettings, moduleName) {
    if (!vtSettings) return "";

    const moduleKey = vtSettings[moduleName]?.apiKey;
    if (moduleKey && moduleKey.trim() !== "") {
        return moduleKey.trim();
    }
    return vtSettings.globalApiKey ? vtSettings.globalApiKey.trim() : "";
}

const domainNetworkData = {};

browser.webRequest.onResponseStarted.addListener(
    async (details) => {
        if (details.tabId === -1) return;

        try {
            const reqUrl = new URL(details.url);
            const domainKey = reqUrl.hostname;
            const cleanDomain = getApexDomain ? getApexDomain(domainKey) : domainKey;

            if (!domainNetworkData[cleanDomain]) {
                domainNetworkData[cleanDomain] = {
                    ip: details.ip || "Unknown",
                    protocol: reqUrl.protocol.replace(":", "").toUpperCase(),
                    externalDomains: new Set(),
                    webSockets: new Set(),
                    requestsCount: 0,
                    securityHeaders: {}
                };
            }

            domainNetworkData[cleanDomain].requestsCount++;
            if (details.ip) domainNetworkData[cleanDomain].ip = details.ip;

            const headers = details.responseHeaders || [];
            const headerMap = {};
            headers.forEach(h => {
                headerMap[h.name.toLowerCase()] = h.value;
            });

            domainNetworkData[cleanDomain].securityHeaders = {
                hsts: !!headerMap['strict-transport-security'],
                csp: !!headerMap['content-security-policy'],
                xframe: headerMap['x-frame-options'] || null,
                xcontent: headerMap['x-content-type-options'] === 'nosniff',
                referrerPolicy: headerMap['referrer-policy'] || null
            };
        } catch (e) {
            console.error("[CookieJar] Error parsing response network info:", e);
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);

async function blockDomain(ruleId, domain, profileData) {
    if (!ruleId) return;

    if (browser.declarativeNetRequest) {
        await browser.declarativeNetRequest.updateDynamicRules({
            addRules: [{
                id: ruleId,
                priority: 1,
                action: { type: "block" },
                condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] }
            }],
            removeRuleIds: [ruleId]
        });
    }
}

browser.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;

    try {
        const url = details.url;
        if (!url.startsWith("http")) return;

        const hostname = new URL(url).hostname;
        const CACHE_TTL = 7 * 24 * 60 * 60 * 1000;

        const storage = await browser.storage.local.get("CookieJar");
        if (!storage.CookieJar) return;

        const profileInstance = Profile.fromJSON(storage.CookieJar);
        const profileData = profileInstance.toJSON();
        const currentPoints = profileData.trustPoints || {};

        let currentScoreObj = currentPoints[hostname];

        if (!currentScoreObj || (Date.now() - (currentScoreObj.timestamp || 0) > CACHE_TTL)) {
            currentScoreObj = await calculateScore(url, hostname, profileInstance);

            if (!profileInstance.trustPoints) profileInstance.trustPoints = {};
            if (!profileInstance.trustHistory) profileInstance.trustHistory = {};
            if (!profileInstance.trustHistory[hostname]) profileInstance.trustHistory[hostname] = [];

            profileInstance.trustPoints[hostname] = currentScoreObj;
            profileInstance.trustHistory[hostname].push(currentScoreObj);

            await browser.storage.local.set({ CookieJar: profileInstance.toJSON() });
        }

        const ruleId = getRuleIdForDomain(hostname);
        const lists = profileData.settings?.lists || { whitelist: [], blacklist: [] };
        const apexDomain = getApexDomain(hostname);

        const isBlacklisted = lists.blacklist.includes(hostname) || lists.blacklist.includes(apexDomain);
        const isWhitelisted = lists.whitelist.includes(hostname) || lists.whitelist.includes(apexDomain);

        const autoBlockThreshold = profileData.settings?.misc?.autoBlockMaliciousSites;
        const shouldBlockByScore = autoBlockThreshold !== undefined && autoBlockThreshold >= currentScoreObj.score;

        if (isWhitelisted) {
            await unblockDomain(ruleId, hostname, profileData);
        } else if (isBlacklisted || shouldBlockByScore) {
            await blockDomain(ruleId, hostname, profileData);
        } else {
            await unblockDomain(ruleId, hostname, profileData);
        }

        if (currentScoreObj) {
            renderBadge(currentScoreObj.score, details.tabId);
        }

        if (currentScoreObj.score <= 35) {
            sendNotification("CookieJar - Low Trust Level", `The site ${hostname} has a low trust score of ${currentScoreObj.score}. Exercise caution.`);
        }

    } catch (e) {
        console.error("[CookieJar] Navigation processing error:", e);
    }
});

browser.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await browser.tabs.get(activeInfo.tabId);
        if (!tab.url || !tab.url.startsWith("http")) {
            browser.action.setBadgeText({ text: "", tabId: activeInfo.tabId });
            return;
        }
        const hostname = new URL(tab.url).hostname;
        const storage = await browser.storage.local.get("CookieJar");
        const trustPoints = storage.CookieJar?.trustPoints || {};
        const siteData = trustPoints[hostname];

        if (siteData) {
            renderBadge(siteData.score, activeInfo.tabId);
        } else {
            browser.action.setBadgeText({ text: "N/A", tabId: activeInfo.tabId });
        }
    } catch (e) {
        console.error("[CookieJar] Error handling tab activation: ", e);
    }
});

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "getDomainInspectorData") {
        const domain = message.domain;
        const cleanDomain = getApexDomain ? getApexDomain(domain) : domain;

        const data = domainNetworkData[cleanDomain] || {
            ip: "Unknown",
            protocol: "N/A",
            externalDomains: new Set(),
            webSockets: new Set(),
            requestsCount: 0,
            securityHeaders: null
        };

        sendResponse({
            ip: data.ip,
            protocol: data.protocol,
            requestsCount: data.requestsCount,
            externalDomains: Array.from(data.externalDomains || []),
            webSockets: Array.from(data.webSockets || []),
            securityHeaders: data.securityHeaders
        });
        return true;
    }
});

browser.tabs.onRemoved.addListener(() => {
    const maxDomains = 100;
    const keys = Object.keys(domainNetworkData);
    if (keys.length > maxDomains) {
        keys.slice(0, keys.length - maxDomains).forEach(k => delete domainNetworkData[k]);
    }
});