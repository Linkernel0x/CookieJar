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
        const bytes = new TextEncoder().encode(downloadUrl);
        const base64 = btoa(String.fromCharCode(...bytes));
        const urlId = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

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

browser.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;

    try {
        const url = details.url;
        if (!url.startsWith("http")) return;

        const hostname = new URL(url).hostname;
        const CACHE_TTL = 7 * 24 * 60 * 60 * 1000;

        const storage = await browser.storage.local.get("CookieJar");
        const profileData = storage.CookieJar || new Profile().toJSON();
        const currentPoints = profileData.trustPoints || {};

        let currentScoreObj = currentPoints[hostname];

        if (!currentScoreObj || (Date.now() - currentScoreObj.timestamp > CACHE_TTL)) {
            currentScoreObj = await calculateScore(url, hostname, profileData);

            if (!profileData.trustPoints) profileData.trustPoints = {};
            profileData.trustPoints[hostname] = currentScoreObj;
            if (!profileData.trustHistory[hostname]) profileData.trustHistory[hostname] = [];
            profileData.trustHistory[hostname].push(currentScoreObj)

            console.log(`[CookieJar] Evaluated ${hostname}: ${currentScoreObj.score}`);
        }

        const ruleId = getRuleIdForDomain(hostname);
        const lists = profileData.settings?.lists || { whitelist: [], blacklist: [] };
        const apexDomain = getApexDomain(hostname);
        const isBlacklisted = lists.blacklist.includes(hostname) || lists.blacklist.includes(apexDomain);
        const isWhitelisted = lists.whitelist.includes(hostname) || lists.whitelist.includes(apexDomain);

        if ((currentScoreObj.score === 0 || (isBlacklisted && !isWhitelisted)) || (profileData.settings?.misc?.autoBlockMaliciousSites >= currentScoreObj.score)) {
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
            renderBadge(siteData.score, activeInfo.tabId)
        } else {
            browser.action.setBadgeText({ text: "N/A", tabId: activeInfo.tabId })
        }
    } catch (e) {
        console.error("[CookieJar] Error handling tab activation: ", e)
    }
});