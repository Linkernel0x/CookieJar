document.addEventListener("DOMContentLoaded", async () => {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });

    const isValidHttp = tab && tab.url && tab.url.startsWith("http");

    if (isValidHttp) {
        try {
            const url = new URL(tab.url);

            const cookies = await browser.cookies.getAll({domain: url.hostname});
            const sessionCookies = cookies.filter(c => c.session).length;
            const persistentCookies = cookies.length - sessionCookies;

            document.getElementById("cookie-count").textContent = `(${cookies.length})`;
            document.getElementById("cookie-breakdown").textContent = `Session: ${sessionCookies} | Persistent: ${persistentCookies}`;

            await updateTrustLevel(url.hostname, tab);

        } catch (e) {
            console.error(e);
            document.getElementById("trust-level").textContent = "N/A";
        }
    } else {
        document.getElementById("trust-level").textContent = "N/A";
    }

    document.getElementById("reload")?.addEventListener("click", async () => {
        if (isValidHttp) {
            await forceTrustFetch(tab);
            window.location.reload();
        }
    });

    document.getElementById("open-cookies")?.addEventListener("click", async () => {
        const [currentTab] = await browser.tabs.query({ active: true, currentWindow: true });
        let domainQuery = "";

        if (currentTab && currentTab.url && currentTab.url.startsWith("http")) {
            const url = new URL(currentTab.url);
            domainQuery = `?domain=${encodeURIComponent(url.hostname)}&tabId=${currentTab.id}`;
        }

        browser.windows.create({
            url: browser.runtime.getURL(`popup/cookies.html${domainQuery}`),
            type: "popup",
            width: 600,
            height: 400
        });
    });

    document.getElementById("open-dashboard")?.addEventListener("click", () => {
        browser.tabs.create({ url: browser.runtime.getURL("dashboard/index.html") });
    });
});

async function updateTrustLevel(hostname, tab) {
    const element = document.getElementById("trust-level");
    if (!hostname) {
        element.textContent = "Unknown";
        return;
    }

    const storage = await browser.storage.local.get("CookieJar");
    const profileData = storage.CookieJar || {};
    const trustPoints = profileData.trustPoints || {};

    let value = trustPoints[hostname];

    if (trustPoints[hostname] === undefined) {
        element.textContent = "Loading...";
        element.style.color = "var(--accent-grey)";
        await forceTrustFetch(tab);

        const storage = await browser.storage.local.get("CookieJar");
        const profileData = storage.CookieJar || {};
        const trustPoints = profileData.trustPoints || {};
        value = trustPoints[hostname];
    }

    let trustCssVar = "--accent-grey";
    if (value.score <= 35) trustCssVar = "--accent-red";
    else if (value.score <= 70) trustCssVar = "--accent-orange";
    else if (value.score <= 100) trustCssVar = "--accent-green";

    element.textContent = `${value.score}`;
    element.style.color = `var(${trustCssVar})`;

    const sourcesTrustLevel = document.getElementById("resources");
    const formattedTime = new Date(value.timestamp).toLocaleString();

    if (sourcesTrustLevel) {
        sourcesTrustLevel.innerHTML = `
        <li>Google: <span style="float: right">${renderStatus(value.sources.googleSafeBrowsing, "boolean")}</span></li>
        <li>Alien Vault: <span style="float: right">${renderStatus(value.sources.alienVaultOTX, "count")} pulses</span></li>
        <li>PhishTank: <span style="float: right">${renderStatus(value.sources.phishTank, "boolean")}</span></li>
        <li>URLScan: <span style="float: right">${renderStatus(value.sources.urlScan, "boolean")}</span></li>
        <li>OpenPhish: <span style="float: right">${renderStatus(value.sources.openPhish, "boolean")}</span></li>
        <li>Tranco Rank: <span style="float: right">${renderStatus(value.sources.trancoRank, "text")}</span></li>
        <li>Domain Age: <span style="float: right">${renderStatus(value.sources.domainAgeDays, "days")}</span></li>
        <li>VirusTotal: <span style="float: right">${renderStatus(value.sources.virusTotal, "count")}</span></li>
        <li style="margin-top: 8px; font-style: italic; color: #a6adc8;">Updated: ${formattedTime}</li>
        `;
    }

    renderBadge(value.score, tab.tabId);
}

async function forceTrustFetch(tab) {
    try {
        const urlObj = new URL(tab.url);
        const storage = await browser.storage.local.get("CookieJar");
        const profileData = storage.CookieJar || {};

        const score = await calculateScore(tab.url, urlObj.hostname, profileData);

        profileData.trustPoints = profileData.trustPoints || {};
        profileData.trustPoints[urlObj.hostname] = score;
        profileData.trustHistory[urlObj.hostname] = profileData.trustHistory[urlObj.hostname] || [];
        profileData.trustHistory[urlObj.hostname].push(score);

        await browser.storage.local.set({CookieJar: profileData});

        renderBadge(score.score, tab.tabId);

        const ruleId = getRuleIdForDomain(urlObj.hostname);
        const lists = profileData.settings?.lists || { whitelist: [], blacklist: [] };
        const apexDomain = getApexDomain(urlObj.hostname);
        const isBlacklisted = lists.blacklist.includes(urlObj.hostname) || lists.blacklist.includes(apexDomain);
        const isWhitelisted = lists.whitelist.includes(urlObj.hostname) || lists.whitelist.includes(apexDomain);

        if ((score.score === 0 || (isBlacklisted && !isWhitelisted)) || (profileData.settings?.misc?.autoBlockMaliciousSites >= score.score)) {
            await blockDomain(ruleId, urlObj.hostname, profileData);
        } else {
            await unblockDomain(ruleId, urlObj.hostname, profileData);
        }

        if (score.score <= 35) {
            sendNotification("CookieJar - Low Trust Level", `The site ${urlObj.hostname} has a low trust score of ${score.score}. Exercise caution.`);
        }
    } catch (e) {

        console.error("[CookieJar] Refetch error:", e);
    }
}