async function calculateScore(urlToCheck, hostname, data) {
    let baseScore = 100;
    const settings = data.settings || {};

    const trancoPromise = settings.ranking?.trancoRank?.enabled
        ? getTrancoRank(hostname)
        : Promise.resolve(null);

    const googlePromise = (settings.trust?.googleSafeBrowsing?.enabled && settings.trust.googleSafeBrowsing.apiKey)
        ? checkGoogleSafeBrowsing(urlToCheck, settings.trust.googleSafeBrowsing.apiKey)
        : Promise.resolve(false);

    const alienVaultPromise = (settings.trust?.AlienVaultOTX?.enabled && settings.trust.AlienVaultOTX.apiKey)
        ? getAlienVaultDomainInfo(hostname, settings.trust.AlienVaultOTX.apiKey)
        : Promise.resolve(0);

    const phishTankPromise = (settings.trust?.phishTank?.enabled)
        ? checkPhishTank(urlToCheck, settings.trust?.phishTank?.apiKey || "")
        : Promise.resolve(false);

    const urlScanPromise = (settings.trust?.urlScan?.enabled)
        ? checkUrlScan(hostname, settings.trust?.urlScan?.apiKey || "")
        : Promise.resolve(false);

    const openPhishPromise = checkOpenPhish(urlToCheck);
    const domainAgePromise = getDomainAge(hostname);

    const results = await Promise.allSettled([
        trancoPromise,
        googlePromise,
        alienVaultPromise,
        phishTankPromise,
        urlScanPromise,
        openPhishPromise,
        domainAgePromise
    ]);

    const rank = results[0].status === "fulfilled" ? results[0].value : null;
    const isGoogleMalicious = results[1].status === "fulfilled" ? results[1].value : null;
    const pulseCount = results[2].status === "fulfilled" ? results[2].value : 0;
    const isPhishTank = results[3].status === "fulfilled" ? results[3].value : null;
    const isUrlScanMalicious = results[4].status === "fulfilled" ? results[4].value : null;
    const isOpenPhish = results[5].status === "fulfilled" ? results[5].value : null;
    const ageInDays = results[6].status === "fulfilled" ? results[6].value : null;

    if (settings.ranking?.trancoRank?.enabled) {
        if (rank && rank > 100000) baseScore -= 10;
        if (!rank) baseScore -= 20;
    }

    if (isGoogleMalicious) baseScore -= 80;
    if (isPhishTank) baseScore -= 80;
    if (isUrlScanMalicious) baseScore -= 70;
    if (isOpenPhish) baseScore -= 80;
    if (pulseCount > 0) baseScore -= Math.min(pulseCount * 10, 50);

    if (ageInDays !== null) {
        if (ageInDays < 30) baseScore -= 30;
        else if (ageInDays < 180) baseScore -= 10;
    }

    return {
        score: Math.max(0, baseScore),
        timestamp: Date.now(),
        sources: {
            googleSafeBrowsing: isGoogleMalicious,
            alienVaultOTX: pulseCount,
            trancoRank: rank || "N/A",
            phishTank: isPhishTank,
            urlScan: isUrlScanMalicious,
            openPhish: isOpenPhish,
            domainAgeDays: ageInDays ? Math.round(ageInDays) : "N/A"
        }
    };
}

async function checkGoogleSafeBrowsing(urlToCheck, apiKey) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(urlToCheck);
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));

        const prefixBytes = hashArray.slice(0, 4);
        const hashPrefix = btoa(String.fromCharCode(...prefixBytes));

        const endpoint = `https://safebrowsing.googleapis.com/v5/hashes:search?key=${apiKey}&hashPrefixes=${encodeURIComponent(hashPrefix)}`;
        const response = await fetch(endpoint);
        if (!response.ok) return false;

        const result = await response.json();
        if (!result.fullHashes) return false;

        const fullHashBase64 = btoa(String.fromCharCode(...hashArray));
        return result.fullHashes.some(match => match.fullHash === fullHashBase64);
    } catch (e) {
        console.error("[CookieJar] Google Safe Browsing error:", e);
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
        if (!response.ok) return 0;
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
        if (data.ranks && data.ranks.length > 0) {
            return data.ranks[0].rank;
        }
        return null;
    } catch {
        return null;
    }
}

async function getDomainAge(hostname) {
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);

        const res = await fetch(`https://rdap.org/domain/${hostname}`, {
            signal: controller.signal
        });
        clearTimeout(timeout);

        if (!res.ok) return null;

        const data = await res.json();
        const registration = data.events?.find(e => e.eventAction === "registration");

        if (!registration) return null;

        const regDate = new Date(registration.eventDate);
        return (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24);
    } catch {
        return null;
    }
}

async function checkPhishTank(urlToCheck, apiKey) {
    try {
        const bodyParams = new URLSearchParams({
            url: urlToCheck,
            format: "json"
        });
        if (apiKey) bodyParams.set("app_key", apiKey);

        const res = await fetch("https://checkurl.phishtank.com/checkurl/", {
            method: "POST",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: bodyParams
        });
        if (!res.ok) return false;
        const data = await res.json();
        return data.results?.valid === true;
    } catch {
        return false;
    }
}

async function checkOpenPhish(urlToCheck){
    try {
        const res = await fetch(`https://openphish.com/feed.txt`);
        if (!res.ok) return false;
        const text = await res.text();
        const urls = text.split("\n");
        return urls.includes(urlToCheck)
    } catch {
        return false;
    }
}

async function checkUrlScan(urlToCheck, apiKey){
    try {
        const submitRes = await fetch("https://urlscan.io/api/v1/scan/", {
            method: "POST",
            headers: {
                "API-Key": apiKey,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: urlToCheck, visibility: "public" })
        });
        if (!submitRes.ok) return null;
        const submitData = await submitRes.json();
        return submitData.result;
    } catch {
        return null;
    }
}