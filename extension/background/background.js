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
        await browser.downloads.pause(downloadItem.id);

        console.log(`[CookieJar] Download intercepted: ${downloadItem.filename} (${downloadItem.url})`);

        const isSafe = await checkVirusTotal(downloadItem.url);

        if (!isSafe) {
            await browser.downloads.cancel(downloadItem.id);
            await browser.downloads.erase({ id: downloadItem.id });
            browser.notifications.create({
                type: "basic",
                title: "CookieJar",
                message: `Blocked download: ${downloadItem.filename}`
            });
        }
    } catch (error) {
        console.error("[CookieJar] Error while handling download:", error);
    }
});

async function checkVirusTotal(downloadItem) {
    //TODO
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