document.addEventListener("DOMContentLoaded", async () => {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });

    if (tab && tab.url) {
        try {
            const url = new URL(tab.url);

            const cookies = await browser.cookies.getAll({ domain: url.hostname });
            document.getElementById("cookie-count").textContent = `(${cookies.length})`;

            await updateTrustLevel(url.hostname);
        } catch (e) {
            document.getElementById("trust-level").textContent = "N/A";
        }
    }

    const links = generateExternalReportLinks(tab.url);
    const linksContainer = document.getElementById("external-links");
    if (linksContainer) {
        linksContainer.innerHTML = `
        <li><a href="${links.googleTransparency}" target="_blank" style="color: var(--accent-blue)">Google Transparency</a></li>
        <li><a href="${links.urlhaus}" target="_blank" style="color: var(--accent-blue)">URLhaus Report</a></li>
        <li><a href="${links.sucuri}" target="_blank" style="color: var(--accent-blue)">Sucuri SiteCheck</a></li>
    `;
    }

    document.getElementById("reload").addEventListener("click", () => {

        window.location.href("popup.html");
    });
    document.getElementById("open-dashboard").addEventListener("click", () => {
        browser.tabs.create({ url: "../dashboard/index.html" });
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

    let trustCssVar;
    if (value <= 35) trustCssVar = "--accent-red";
    else if (value <= 65) trustCssVar = "--accent-orange";
    else if (value <= 100) trustCssVar = "--accent-green";
    else trustCssVar = "--accent-grey";

    element.textContent = `${value}`;
    element.style.color = `var(${trustCssVar})`;

    const sourcesTrustLevel = document.getElementById("external-links");
    if (sourcesTrustLevel) {
        sourcesTrustLevel.innerHTML = `
        <li>Google Transparency <span style="color: #a6adc8; text-align: right">${}</span></li>
    `;
    }
}

function forceFetch() {
    
}

function generateExternalReportLinks(targetUrl) {
    const encodedUrl = encodeURIComponent(targetUrl);

    return {
        sucuri: `https://sitecheck.sucuri.net/?scan=${encodedUrl}`,
        googleTransparency: `https://transparencyreport.google.com/safe-browsing/search?url=${encodedUrl}`,
        mcAfeeSiteAdvisor: `https://www.siteadvisor.com/sitereport.html?url=${encodedUrl}`,
        urlhaus: `https://urlhaus.abuse.ch/browse.php?search=${encodedUrl}`,
        yandex: `https://www.yandex.com/infected?url=${encodedUrl}`
    };
}