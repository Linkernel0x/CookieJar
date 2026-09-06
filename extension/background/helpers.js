async function sendNotification(title, message) {
    const storage = await browser.storage.local.get("CookieJar");
    const profileData = storage.CookieJar || new Profile().toJSON();
    const allow_notifications = profileData.settings?.misc?.allowNotification;

    if (allow_notifications) {
        browser.notifications.create({
            type: "basic",
            iconUrl: "icons/icon.svg",
            title: title,
            message: message
        });
    }
}

async function renderBadge(value) {
    const storage = await browser.storage.local.get("CookieJar");
    const profileData = storage.CookieJar || new Profile().toJSON();
    const allow_badge = profileData.settings?.misc?.renderColorBadge;

    if (!allow_badge) {
        const tabId = await getCurrentTabId();
        browser.action.setBadgeText({ text: "", tabId: tabId });
        return;
    }

    let color = "#a6adc8";

    if (value <= 35) color = "#f38ba8";
    else if (value <= 65) color = "#fab387";
    else if (value <= 100) color = "#a6e3a1";

    const tabId = await getCurrentTabId();

    browser.action.setBadgeText({
        text: (value !== null && value !== undefined) ? value.toString() : "N/A",
        tabId: tabId
    });

    browser.action.setBadgeBackgroundColor({
        color: color,
        tabId: tabId
    });
}

async function getCurrentTabId() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    return tab.id;
}

async function calculateScore(urlToCheck, hostname, data) {
    let baseScore = 100;
    const settings = data.settings || {};
    const trust = settings.trust || {};

    const results = await Promise.allSettled([
        trust.trancoRank?.enabled ? getTrancoRank(hostname) : Promise.resolve({ status: "SKIPPED", value: null }),
        (trust.googleSafeBrowsing?.enabled && trust.googleSafeBrowsing.apiKey)
            ? checkGoogleSafeBrowsing(urlToCheck, trust.googleSafeBrowsing.apiKey) : Promise.resolve({ status: "SKIPPED", value: null }),
        (trust.AlienVaultOTX?.enabled && trust.AlienVaultOTX.apiKey)
            ? getAlienVaultDomainInfo(hostname, trust.AlienVaultOTX.apiKey) : Promise.resolve({ status: "SKIPPED", value: null }),
        trust.phishTank?.enabled ? checkPhishTank(urlToCheck, trust.phishTank.apiKey || "") : Promise.resolve({ status: "SKIPPED", value: null }),
        trust.urlScan?.enabled ? checkUrlScan(hostname, trust.urlScan.apiKey || "") : Promise.resolve({ status: "SKIPPED", value: null }),
        checkOpenPhish(urlToCheck),
        getDomainAge(hostname),
        (settings.virustotal?.trustLevel?.enabled)
            ? checkVirusTotalDomain(hostname, settings.virustotal.trustLevel.apiKey || settings.virustotal.globalApiKey) : Promise.resolve({ status: "SKIPPED", value: null })
    ]);

    const extractRes = (index) => results[index].status === "fulfilled" ? results[index].value : { status: "ERROR", value: null };

    const trancoRes = extractRes(0);
    const googleRes = extractRes(1);
    const alienRes = extractRes(2);
    const phishTankRes = extractRes(3);
    const urlScanRes = extractRes(4);
    const openPhishRes = extractRes(5);
    const ageRes = extractRes(6);
    const vtRes = extractRes(7);

    if (vtRes.status === "SUCCESS" && vtRes.value > 0) {
        baseScore -= Math.min(vtRes.value * 15, 80);
    }

    if (trancoRes.status === "SUCCESS") {
        if (trancoRes.value && trancoRes.value > 100000) baseScore -= 10;
        if (!trancoRes.value) baseScore -= 20;
    }

    if (googleRes.status === "SUCCESS" && googleRes.value === true) baseScore -= 80;
    if (phishTankRes.status === "SUCCESS" && phishTankRes.value === true) baseScore -= 80;
    if (urlScanRes.status === "SUCCESS" && urlScanRes.value === true) baseScore -= 70;
    if (openPhishRes.status === "SUCCESS" && openPhishRes.value === true) baseScore -= 80;
    if (alienRes.status === "SUCCESS" && alienRes.value > 0) baseScore -= Math.min(alienRes.value * 10, 50);

    if (ageRes.status === "SUCCESS" && ageRes.value !== null) {
        if (ageRes.value < 30) baseScore -= 30;
        else if (ageRes.value < 180) baseScore -= 10;
    }

    return {
        score: Math.max(0, baseScore),
        timestamp: Date.now(),
        sources: {
            googleSafeBrowsing: googleRes,
            alienVaultOTX: alienRes,
            trancoRank: trancoRes,
            phishTank: phishTankRes,
            urlScan: urlScanRes,
            openPhish: openPhishRes,
            virusTotal: vtRes,
            domainAgeDays: ageRes
        }
    };
}
async function getDomainAge(hostname) {
    const domain = getApexDomain(hostname);
    try {
        const primaryRes = await fetch(`https://rdap.org/domain/${domain}`);
        if (primaryRes.ok) {
            const data = await primaryRes.json();
            const days = extractDaysFromRdap(data);
            return days !== null
                ? { status: "SUCCESS", value: days }
                : { status: "ERROR", value: null };
        }

        if (primaryRes.status === 404) {
            const ianaData = await queryIanaBootstrap(domain);
            if (ianaData) {
                const days = extractDaysFromRdap(ianaData);
                return days !== null
                    ? { status: "SUCCESS", value: days }
                    : { status: "ERROR", value: null };
            }
        }

        return { status: "ERROR", value: null };
    } catch (error) {
        console.warn(`[CookieJar] Error fetching domain age for ${domain}:`, error);
        return { status: "ERROR", value: null };
    }
}

function extractDaysFromRdap(rdapData) {
    if (!rdapData || !rdapData.events || !Array.isArray(rdapData.events)) return null;

    const regEvent = rdapData.events.find(
        e => e.eventAction === "registration" || e.eventAction === "date created"
    );
    if (!regEvent || !regEvent.eventDate) return null;

    const creationDate = new Date(regEvent.eventDate);
    if (isNaN(creationDate.getTime())) return null;

    const diffMs = Date.now() - creationDate.getTime();
    const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    return days >= 0 ? days : null;
}

async function queryIanaBootstrap(domain) {
    try {
        const parts = domain.split(".");
        const tld = parts[parts.length - 1].toLowerCase();

        const res = await fetch("https://data.iana.org/rdap/dns.json");
        if (!res.ok) return null;

        const bootstrapData = await res.json();
        let rdapServiceUrl = null;

        for (const entry of bootstrapData.services) {
            if (entry[0].includes(tld)) {
                rdapServiceUrl = entry[1][0];
                break;
            }
        }

        if (!rdapServiceUrl) return null;

        const fallbackResponse = await fetch(`${rdapServiceUrl}domain/${domain}`);
        if (!fallbackResponse.ok) return null;

        return await fallbackResponse.json();
    } catch {
        return null;
    }
}

function getApexDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    return parts.slice(-2).join('.');
}

async function checkUrlScan(hostname, apiKey) {
    try {
        const headers = {};
        if (apiKey) headers["API-Key"] = apiKey;

        const res = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${hostname}`, { headers });
        if (!res.ok) return { status: "ERROR", value: null };

        const data = await res.json();
        if (!data.results || data.results.length === 0) return { status: "SUCCESS", value: false };

        return { status: "SUCCESS", value: data.results[0].verdicts?.overall?.malicious === true };
    } catch {
        return { status: "ERROR", value: null };
    }
}

async function checkVirusTotalDomain(domain, apiKey) {
    if (!apiKey) return { status: "SKIPPED", value: null };
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
            headers: { "x-apikey": apiKey }
        });
        if (!response.ok) return { status: "ERROR", value: null };

        const data = await response.json();
        const maliciousCount = data.data?.attributes?.last_analysis_stats?.malicious || 0;
        return { status: "SUCCESS", value: maliciousCount };
    } catch {
        return { status: "ERROR", value: null };
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
        if (!response.ok) return { status: "ERROR", value: null };

        const result = await response.json();
        if (!result.fullHashes) return { status: "SUCCESS", value: false };

        const fullHashBase64 = btoa(String.fromCharCode(...hashArray));
        const isMalicious = result.fullHashes.some(match => match.fullHash === fullHashBase64);
        return { status: "SUCCESS", value: isMalicious };
    } catch {
        return { status: "ERROR", value: null };
    }
}

async function getAlienVaultDomainInfo(domain, apiKey) {
    try {
        const endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`;
        const response = await fetch(endpoint, { headers: { "X-OTX-API-KEY": apiKey } });
        if (!response.ok) return { status: "ERROR", value: null };
        const data = await response.json();
        return { status: "SUCCESS", value: data.pulse_info?.count || 0 };
    } catch {
        return { status: "ERROR", value: null };
    }
}

async function getTrancoRank(domain) {
    try {
        const response = await fetch(`https://tranco-list.eu/api/ranks/domain/${domain}`);
        if (!response.ok) return { status: "ERROR", value: null };
        const data = await response.json();
        const rank = (data.ranks && data.ranks.length > 0) ? data.ranks[0].rank : null;
        return { status: "SUCCESS", value: rank };
    } catch {
        return { status: "ERROR", value: null };
    }
}

async function checkPhishTank(urlToCheck, apiKey) {
    if (!apiKey) return { status: "SKIPPED", value: null };
    try {
        const bodyParams = new URLSearchParams({ url: urlToCheck, format: "json", app_key: apiKey });
        const res = await fetch("https://checkurl.phishtank.com/checkurl/", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "phishTank/CookieJarExtension" },
            body: bodyParams
        });
        if (!res.ok) return { status: "ERROR", value: null };
        const data = await res.json();
        return { status: "SUCCESS", value: data.results?.valid === true };
    } catch {
        return { status: "ERROR", value: null };
    }
}

async function checkOpenPhish(urlToCheck) {
    try {
        const storage = await browser.storage.local.get("openPhishCache");
        let feed = storage.openPhishCache?.data || [];
        const lastFetch = storage.openPhishCache?.timestamp || 0;

        if (Date.now() - lastFetch > 60 * 60 * 1000 || feed.length === 0) {
            const res = await fetch("https://openphish.com/feed.txt");
            if (res.ok) {
                const text = await res.text();
                feed = text.split("\n").map(u => u.trim()).filter(Boolean);
                await browser.storage.local.set({ openPhishCache: { data: feed, timestamp: Date.now() } });
            } else if (feed.length === 0) {
                return { status: "ERROR", value: null };
            }
        }

        return { status: "SUCCESS", value: feed.includes(urlToCheck) };
    } catch {
        return { status: "ERROR", value: null };
    }
}

const renderStatus = (obj, type) => {
    if (!obj || obj.status === "SKIPPED") return `<span style="color: #6c7086;">Disabled</span>`;
    if (obj.status === "ERROR") return `<span style="color: #f38ba8;">Error/Unreachable</span>`;

    if (type === "boolean") {
        return obj.value ? `<span style="color: #f38ba8; font-weight: bold;">Malicious</span>` : `<span style="color: #a6e3a1;">Safe</span>`;
    }
    if (type === "count") {
        return `<span style="color: #cba6f7;">${obj.value}</span>`;
    }
    if (type === "days") {
        return obj.value !== null ? `<span style="color: #89b4fa;">${obj.value} days</span>` : `<span style="color: #f38ba8;">N/A</span>`;
    }
    return `<span style="color: #a6adc8;">${obj.value ?? 'N/A'}</span>`;
};

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
function generateID() {
    return 'id_' + Math.random().toString(36).substring(2, 9) + Date.now().toString(36);
}

async function freezeCookie(profile, cookie) {
    const freezeId = generateID();

    const protocol = cookie.secure ? "https://" : "http://";
    const cleanDomain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
    const cookieUrl = `${protocol}${cleanDomain}${cookie.path}`;

    await browser.cookies.remove({
        url: cookieUrl,
        name: cookie.name,
        storeId: cookie.storeId
    });

    if (!profile.frozenCookies) {
        profile.frozenCookies = {};
    }

    profile.frozenCookies[freezeId] = {
        id: freezeId,
        domain: cleanDomain,
        originalCookie: cookie,
        frozenAt: Date.now()
    };

    await browser.storage.local.set({ CookieJar: profile.toJSON() });
    return freezeId;
}

async function unfreezeCookie(profile, freezeId) {
    const frozenItem = profile.frozenCookies?.[freezeId];
    if (!frozenItem) return false;

    const c = frozenItem.originalCookie;
    const protocol = c.secure ? "https://" : "http://";
    const cookieUrl = `${protocol}${frozenItem.domain}${c.path}`;

    await browser.cookies.set({
        url: cookieUrl,
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite,
        expirationDate: c.expirationDate,
        storeId: c.storeId
    });

    delete profile.frozenCookies[freezeId];

    await browser.storage.local.set({ CookieJar: profile.toJSON() });
    return true;
}

function getFrozenCookies(profile, domain) {
    if (!profile?.frozenCookies) return [];

    return Object.values(profile.frozenCookies)
        .filter(frozen => domain === frozen.domain || domain.endsWith('.' + frozen.domain) || frozen.domain.endsWith('.' + domain))
        .map(frozen => ({
            key: frozen.originalCookie.name,
            value: frozen.originalCookie.value,
            isFrozen: true,
            freezeId: frozen.id,
            frozenAt: frozen.frozenAt,
            raw: frozen.originalCookie
        }));
}

async function blockDomain(ruleId, domain){
    await browser.declarativeNetRequest.updateDynamicRules({
        addRules: [
            {
                id: ruleId,
                priority: 1,
                action: {type: "block"},
                condition: {
                    urlFilter: `||${domain}^`,
                    resourceTypes: ["main_frame", "sub_frame", "script"]
                }
            }
        ],
        removeRuleIds: [ruleId]
    })
}

async function unblockDomain(ruleId){
    await browser.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [ruleId]
    });
}