browser.runtime.onInstalled.addListener(async () => {
    console.log("[CookieJar] Extension Installed/Updated!");

    try {
        const storage = await browser.storage.local.get("CookieJar");

        if (storage.CookieJar) {
            console.log("[CookieJar] Existing profile found. Retaining data.");
        } else {
            const initialProfile = new Profile();
            await browser.storage.local.set({
                CookieJar: initialProfile.toJSON()
            });
            console.log("[CookieJar] No profile found. Initialized new profile.");
        }
    } catch (error) {
        console.error("[CookieJar] Error initializing storage:", error);
    }
});

browser.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;

    try {
        const urlObj = new URL(details.url);
        const url = details.url;
        const hostname = urlObj.hostname;

        const storage = await browser.storage.local.get("CookieJar");
        const profileData = storage.CookieJar || new Profile().toJSON();
        const trustPoints = profileData.trustPoints || {};

        if (!trustPoints[hostname]) {
            const score = await calculateScore(url, hostname, profileData);

            trustPoints[hostname] = score;
            profileData.trustPoints = trustPoints;

            await browser.storage.local.set({ CookieJar: profileData });
            console.log(`[CookieJar] Evaluated ${hostname}: ${score}/100`);
        }
    } catch (e) {
        console.error("[CookieJar] Navigation processing error:", e);
    }
});

async function calculateScore(urlToCheck, hostname, data) {
    let baseScore = 100;
    const settings = data.settings || {};

    const trancoPromise = settings.ranking?.trancoRank?.enabled
        ? getTrancoRank(hostname)
        : null;

    const googlePromise = (settings.trust?.googleSafeBrowsing?.enabled && settings.trust.googleSafeBrowsing.apiKey)
        ? checkGoogleSafeBrowsing(urlToCheck, settings.trust.googleSafeBrowsing.apiKey)
        : false;

    const alienVaultPromise = (settings.trust?.AlienVaultOTX?.enabled && settings.trust.AlienVaultOTX.apiKey)
        ? getAlienVaultDomainInfo(hostname, settings.trust.AlienVaultOTX.apiKey)
        : 0;

    const [isUrlhausMalicious, rank, isGoogleMalicious, pulseCount] = await Promise.all([
        checkURLhaus(urlToCheck),
        trancoPromise,
        googlePromise,
        alienVaultPromise
    ]);

    if (isUrlhausMalicious) baseScore -= 70;

    if (settings.ranking?.trancoRank?.enabled) {
        if (rank && rank > 100000) baseScore -= 10;
        if (!rank) baseScore -= 20;
    }

    if (isGoogleMalicious) baseScore -= 80;
    if (pulseCount > 0) baseScore -= Math.min(pulseCount * 10, 50);

    result = Math.max(0, baseScore)
    return {
        score: result,
        timestamp: Date.now(),
        sources: {
            googleSafeBrowsing: isGoogleMalicious,
            alienVaultOTX: pulseCount,
            trancoRank: rank,
            URLhaus: isUrlhausMalicious,
        }
    };
}

async function checkGoogleSafeBrowsing(urlToCheck, apiKey) {
    try {
        const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
        const body = {
            client: { clientId: "cookiejar-extension", clientVersion: "1.0.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: urlToCheck }]
            }
        };

        const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        const data = await response.json();
        return !!(data.matches && data.matches.length > 0);
    } catch {
        return false;
    }
}

async function getAlienVaultDomainInfo(domain, apiKey) {
    try {
        const endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`;
        const response = await fetch(endpoint, {
            method: "GET",
            headers: { "X-OTX-API-KEY": apiKey }
        });
        const data = await response.json();
        return data.pulse_info?.count || 0;
    } catch {
        return 0;
    }
}

async function getTrancoRank(domain) {
    try {
        const response = await fetch(`https://tranco-list.eu/api/ranks/domain/${domain}`);
        if (!response.ok) return null;
        const data = await response.json();
        return data.ranks[0]?.rank || null;
    } catch {
        return null;
    }
}

async function checkURLhaus(urlToCheck) {
    try {
        const response = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ url: urlToCheck })
        });

        if (!response.ok) return false;

        const data = await response.json();
        return data.query_status === "ok" && data.url_status === "online";
    } catch (e) {
        console.error("[CookieJar] URLhaus check failed:", e);
        return false;
    }
}