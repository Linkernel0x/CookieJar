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

        const apiKey = settings.downloadScan?.apiKey || settings.globalApiKey;
        if (!apiKey) return;

        const isSafe = await checkDownloadUrlSafety(downloadItem.url, apiKey);
        const minResults = settings.downloadScan?.minimumResults || 1;

        if (isSafe !== null && isSafe >= minResults) {
            await browser.downloads.cancel(downloadItem.id);
            await browser.downloads.erase({ id: downloadItem.id });

            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/icon-48.png",
                title: "CookieJar - Download Bloccato",
                message: `File malevolo intercettato: ${downloadItem.filename}`
            });
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
        const urlId = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

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

browser.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;

    try {
        const url = details.url;
        if (!url.startsWith("http")) return;

        const urlObj = new URL(url);
        const hostname = urlObj.hostname;

        const storage = await browser.storage.local.get("CookieJar");
        const profileData = storage.CookieJar || new Profile().toJSON();
        const trustPoints = profileData.trustPoints || {};
        const CACHE_TTL = 7 * 24 * 60 * 60 * 1000;

        if (!trustPoints[hostname] || (Date.now() - trustPoints[hostname].timestamp > CACHE_TTL)) {
            const score = await calculateScore(url, hostname, profileData);

            const currentStorage = await browser.storage.local.get("CookieJar");
            const currentProfile = currentStorage.CookieJar || profileData;
            currentProfile.trustPoints = currentProfile.trustPoints || {};
            currentProfile.trustPoints[hostname] = score;

            await browser.storage.local.set({ CookieJar: currentProfile });
            console.log(`[CookieJar] Evaluated ${hostname}: ${score.score}`);
        }
    } catch (e) {
        console.error("[CookieJar] Navigation processing error:", e);
    }
});