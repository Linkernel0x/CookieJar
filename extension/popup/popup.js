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
            domainQuery = `?domain=${encodeURIComponent(url.hostname)}`;
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

    renderBadge(value.score);
}

async function forceTrustFetch(tab) {
    try {
        const urlObj = new URL(tab.url);
        const storage = await browser.storage.local.get("CookieJar");
        const profileData = storage.CookieJar || {};

        const score = await calculateScore(tab.url, urlObj.hostname, profileData);

        profileData.trustPoints = profileData.trustPoints || {};
        profileData.trustPoints[urlObj.hostname] = score;

        await browser.storage.local.set({CookieJar: profileData});
    } catch (e) {
        console.error("[CookieJar] Refetch error:", e);
    }
}