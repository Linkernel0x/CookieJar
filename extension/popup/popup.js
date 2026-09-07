document.addEventListener("DOMContentLoaded", async () => {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });

    const isValidHttp = tab && tab.url && tab.url.startsWith("http");

    if (isValidHttp) {
        try {
            const url = new URL(tab.url);

            const cookies = await browser.cookies.getAll({domain: url.hostname});
            const sessionCookies = cookies.filter(c => c.session).length;
            const persistentCookies = cookies.length - sessionCookies;

            const cookieCountElem = document.getElementById("cookie-count");
            const cookieBreakdownElem = document.getElementById("cookie-breakdown");
            if (cookieCountElem) cookieCountElem.textContent = `(${cookies.length})`;
            if (cookieBreakdownElem) cookieBreakdownElem.textContent = `Session: ${sessionCookies} | Persistent: ${persistentCookies}`;

            await updateTrustLevel(url.hostname, tab);

        } catch (e) {
            console.error(e);
            const trustElem = document.getElementById("trust-level");
            if (trustElem) trustElem.textContent = "N/A";
        }
    } else {
        const trustElem = document.getElementById("trust-level");
        if (trustElem) trustElem.textContent = "N/A";
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

    document.getElementById("open-net-analysis")?.addEventListener("click", async () => {
        const [currentTab] = await browser.tabs.query({ active: true, currentWindow: true });
        let domainQuery = "";

        if (currentTab && currentTab.url && currentTab.url.startsWith("http")) {
            const url = new URL(currentTab.url);
            domainQuery = `?domain=${encodeURIComponent(url.hostname)}`;
        }

        browser.windows.create({
            url: browser.runtime.getURL(`popup/inspector.html${domainQuery}`),
            type: "popup",
            width: 800,
            height: 600
        });
    });

    document.getElementById("open-dashboard")?.addEventListener("click", () => {
        browser.tabs.create({ url: browser.runtime.getURL("dashboard/index.html") });
    });
});

async function updateTrustLevel(hostname, tab) {
    const element = document.getElementById("trust-level");
    if (!hostname) {
        if (element) element.textContent = "Unknown";
        return;
    }

    let storage = await browser.storage.local.get("CookieJar");
    let profileData = storage.CookieJar || {};
    let trustPoints = profileData.trustPoints || {};

    let value = trustPoints[hostname];

    if (value === undefined) {
        if (element) {
            element.textContent = "Loading...";
            element.style.color = "var(--accent-grey)";
        }

        value = await forceTrustFetch(tab);
    }

    if (!value || typeof value.score !== "number") {
        if (element) {
            element.textContent = "Unknown";
            element.style.color = "var(--accent-grey)";
        }
        return;
    }

    let trustCssVar = "--accent-grey";
    if (value.score <= 35) trustCssVar = "--accent-red";
    else if (value.score <= 70) trustCssVar = "--accent-orange";
    else if (value.score <= 100) trustCssVar = "--accent-green";

    if (element) {
        element.style.color = `var(${trustCssVar})`;
        element.textContent = `${value.score}`;
    }

    const sourcesTrustLevel = document.getElementById("resources");
    if (sourcesTrustLevel && typeof renderStatus === "function") {
        const sources = value.sources || {};
        const formattedTime = value.timestamp
            ? new Date(value.timestamp).toLocaleString()
            : "N/A";

        sourcesTrustLevel.innerHTML = `
            <li>Google: <span style="float: right">${renderStatus(sources.googleSafeBrowsing, "boolean")}</span></li>
            <li>Alien Vault: <span style="float: right">${renderStatus(sources.alienVaultOTX, "count")} pulses</span></li>
            <li>PhishTank: <span style="float: right">${renderStatus(sources.phishTank, "boolean")}</span></li>
            <li>URLScan: <span style="float: right">${renderStatus(sources.urlScan, "boolean")}</span></li>
            <li>OpenPhish: <span style="float: right">${renderStatus(sources.openPhish, "boolean")}</span></li>
            <li>Tranco Rank: <span style="float: right">${renderStatus(sources.trancoRank, "text")}</span></li>
            <li>Domain Age: <span style="float: right">${renderStatus(sources.domainAgeDays, "days")}</span></li>
            <li>VirusTotal: <span style="float: right">${renderStatus(sources.virusTotal, "count")}</span></li>
            <li style="margin-top: 8px; font-style: italic; color: #a6adc8;">Updated: ${formattedTime}</li>
        `;
    }

    if (typeof renderBadge === "function" && tab) {
        renderBadge(value.score, tab.tabId || tab.id);
    }
}

async function forceTrustFetch(tab) {
    try {
        const urlObj = new URL(tab.url);
        const storage = await browser.storage.local.get("CookieJar");

        const profileInstance = Profile.fromJSON(storage.CookieJar);
        const profileData = profileInstance.toJSON();

        const score = await calculateScore(tab.url, urlObj.hostname, profileInstance);

        profileInstance.trustPoints = profileInstance.trustPoints || {};
        profileInstance.trustHistory = profileInstance.trustHistory || {};

        if (!profileInstance.trustHistory[urlObj.hostname]) {
            profileInstance.trustHistory[urlObj.hostname] = [];
        }

        profileInstance.trustPoints[urlObj.hostname] = score;
        profileInstance.trustHistory[urlObj.hostname].push(score);

        await browser.storage.local.set({ CookieJar: profileInstance.toJSON() });

        if (typeof renderBadge === "function") {
            renderBadge(score.score, tab.tabId || tab.id);
        }

        const ruleId = typeof getRuleIdForDomain === "function" ? getRuleIdForDomain(urlObj.hostname) : null;
        const lists = profileData.settings?.lists || { whitelist: [], blacklist: [] };
        const apexDomain = typeof getApexDomain === "function" ? getApexDomain(urlObj.hostname) : urlObj.hostname;
        const isBlacklisted = lists.blacklist.includes(urlObj.hostname) || lists.blacklist.includes(apexDomain);
        const isWhitelisted = lists.whitelist.includes(urlObj.hostname) || lists.whitelist.includes(apexDomain);

        const autoBlockThreshold = profileData.settings?.misc?.autoBlockMaliciousSites;
        const shouldBlockByScore = autoBlockThreshold !== undefined && autoBlockThreshold >= score.score;

        if (ruleId !== null) {
            if ((score.score === 0 || (isBlacklisted && !isWhitelisted)) || shouldBlockByScore) {
                if (typeof blockDomain === "function") await blockDomain(ruleId, urlObj.hostname, profileData);
            } else {
                if (typeof unblockDomain === "function") await unblockDomain(ruleId, urlObj.hostname, profileData);
            }
        }

        if (score.score <= 35 && typeof sendNotification === "function") {
            sendNotification("CookieJar - Low Trust Level", `The site ${urlObj.hostname} has a low trust score of ${score.score}. Exercise caution.`);
        }

        return score;

    } catch (e) {
        console.error("[CookieJar] Refetch error:", e);
        return null;
    }
}