async function calculateScore(urlToCheck, hostname, data) {
    let baseScore = 100;
    const settings = data.settings || {};

    const trancoPromise = settings.trust?.trancoRank?.enabled
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

    const vtApiKey = settings.virustotal?.trustLevel?.apiKey || settings.virustotal?.globalApiKey || "";
    const vtPromise = (settings.virustotal?.trustLevel?.enabled && vtApiKey)
        ? checkVirusTotalDomain(hostname, vtApiKey)
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
        domainAgePromise,
        vtPromise
    ]);

    const rank = results[0].status === "fulfilled" ? results[0].value : null;
    const isGoogleMalicious = results[1].status === "fulfilled" ? results[1].value : false;
    const pulseCount = results[2].status === "fulfilled" ? results[2].value : 0;
    const isPhishTank = results[3].status === "fulfilled" ? results[3].value : false;
    const isUrlScanMalicious = results[4].status === "fulfilled" ? results[4].value : false;
    const isOpenPhish = results[5].status === "fulfilled" ? results[5].value : false;
    const ageInDays = results[6].status === "fulfilled" ? results[6].value : null;
    const vtMaliciousCount = results[7].status === "fulfilled" ? results[7].value : false;

    if (vtMaliciousCount > 0) {
        baseScore -= Math.min(vtMaliciousCount * 15, 80);
    }

    if (settings.trust?.trancoRank?.enabled) {
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
            virusTotal: vtMaliciousCount,
            domainAgeDays: ageInDays ? Math.round(ageInDays) : "N/A"
        }
    };
}

async function checkUrlScan(hostname, apiKey) {
    try {
        const headers = {};
        if (apiKey) headers["API-Key"] = apiKey;

        const res = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${hostname}`, {
            method: "GET",
            headers: headers
        });
        if (!res.ok) return false;

        const data = await res.json();
        if (!data.results || data.results.length === 0) return false;

        return data.results[0].verdicts?.overall?.malicious === true;
    } catch {
        return false;
    }
}

async function checkVirusTotalDomain(domain, apiKey) {
    if (!apiKey) return false;
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
            method: "GET",
            headers: { "x-apikey": apiKey }
        });
        if (!response.ok) return false;

        const data = await response.json();
        return data.data?.attributes?.last_analysis_stats?.malicious || 0;
    } catch {
        return false;
    }
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
    const primaryUrl = `https://rdap.org/domain/${domain}`;

    try {
        let response = await fetch(primaryUrl);
        if (response.ok) {
            return await response.json();
        }

        if (response.status === 404) {
            console.warn(`[CookieJar] RDAP.org 404 per ${domain}. Avvio fallback su IANA bootstrap...`);
            return await queryIanaBootstrap(domain);
        }

        throw new Error(`HTTP error! status: ${response.status}`);
    } catch (error) {
        console.error("[CookieJar] Errore critico RDAP:", error);
        return null;
    }
}

async function queryIanaBootstrap(domain) {
    const parts = domain.split(".");
    const tld = parts[parts.length - 1].toLowerCase();

    const ianaBootstrapUrl = "https://data.iana.org/rdap/dns.json";
    const res = await fetch(ianaBootstrapUrl);

    if (!res.ok) throw new Error("Couldn't load bootstrap IANA");

    const bootstrapData = await res.json();

    let rdapServiceUrl = null;
    for (const entry of bootstrapData.services) {
        const tldsInEntry = entry[0];
        const urls = entry[1];
        if (tldsInEntry.includes(tld)) {
            rdapServiceUrl = urls[0];
            break;
        }
    }

    if (!rdapServiceUrl) {
        throw new Error(`No RDAP found on IANA .${tld}`);
    }

    const finalQuery = `${rdapServiceUrl}domain/${domain}`;
    const fallbackResponse = await fetch(finalQuery);

    if (!fallbackResponse.ok) {
        throw new Error(`Failed registry endpoint: ${finalQuery}`);
    }

    return await fallbackResponse.json();
}

async function checkPhishTank(urlToCheck, apiKey) {
    try {
        const bodyParams = new URLSearchParams({
            url: urlToCheck,
            format: "json"
        });

        if (apiKey) {
            bodyParams.set("app_key", apiKey);
        } else {
            return false;
        }

        const res = await fetch("https://checkurl.phishtank.com/checkurl/", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "phishTank/CookieJarExtension",
            },
            body: bodyParams
        });

        if (!res.ok) return false;
        const data = await res.json();
        return data.results?.valid === true;
    } catch {
        return false;
    }
}

async function checkOpenPhish(urlToCheck) {
    try {
        const res = await fetch(`https://openphish.com/feed.txt`);
        if (!res.ok) return false;
        const text = await res.text();
        const urls = text.split("\n");
        return urls.includes(urlToCheck);
    } catch {
        return false;
    }
}