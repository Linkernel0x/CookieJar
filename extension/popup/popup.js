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

            await updateTrustLevel(url.hostname);

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

async function updateTrustLevel(hostname) {
    const element = document.getElementById("trust-level");
    if (!hostname) {
        element.textContent = "Unknown";
        return;
    }

    const storage = await browser.storage.local.get("CookieJar");
    const profileData = storage.CookieJar || {};
    const trustPoints = profileData.trustPoints || {};

    let value = trustPoints[hostname];

    if (value === undefined) {
        element.textContent = "Loading...";
        element.style.color = "var(--accent-grey)";
        return;
    }

    let trustCssVar = "--accent-grey";
    if (value.score <= 35) trustCssVar = "--accent-red";
    else if (value.score <= 65) trustCssVar = "--accent-orange";
    else if (value.score <= 100) trustCssVar = "--accent-green";

    element.textContent = `${value.score}`;
    element.style.color = `var(${trustCssVar})`;

    const sourcesTrustLevel = document.getElementById("resources");
    const formattedTime = new Date(value.timestamp).toLocaleString();
    if (sourcesTrustLevel) {
        sourcesTrustLevel.innerHTML = `
        <li>Google: <span style="color: #a6adc8; float: right">${value.sources.googleSafeBrowsing === null ? '--' : (value.sources.googleSafeBrowsing ? 'Malicious' : 'Safe')}</span></li>
        <li>Alien Vault: <span style="color: #a6adc8; float: right">${value.sources.alienVaultOTX === null ? '--' : value.sources.alienVaultOTX} pulses</span></li>
        <li>PhishTank: <span style="color: #a6adc8; float: right">${value.sources.phishTank === null ? '--' : (value.sources.phishTank ? 'Malicious' : 'Safe')}</span></li>
        <li>URLScan: <span style="color: #a6adc8; float: right">${value.sources.urlScan === null ? '--' : (value.sources.urlScan ? 'Malicious' : 'Safe')}</span></li>
        <li>OpenPhish: <span style="color: #a6adc8; float: right">${value.sources.openPhish === null ? '--' : (value.sources.openPhish ? 'Malicious' : 'Safe')}</span></li>
        <li>Tranco Rank: <span style="color: #a6adc8; float: right">${value.sources.trancoRank === null ? '--' : value.sources.trancoRank}</span></li>
        <li>Domain Age: <span style="color: #a6adc8; float: right">${(value.sources.domainAgeDays !== 'N/A' && value.sources.domainAgeDays !== null) ? value.sources.domainAgeDays + ' days' : 'N/A'}</span></li>
        <li>VirusTotal: <span style="color: #a6adc8; float: right">${value.sources.virusTotal === null ? '--' : value.sources.virusTotal}</span></li>
        <li style="margin-top: 8px; font-style: italic;">Updated: ${formattedTime}</li>
        `;
    }

    browser.action.setBadgeText({ text: value.score.toString(), tabId: await getCurrentTabId() });
    browser.action.setBadgeBackgroundColor({ color: getComputedStyle(document.documentElement).getPropertyValue(trustCssVar).trim() });
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

async function getCurrentTabId() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    return tab.id;
}
