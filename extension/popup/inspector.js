document.addEventListener("DOMContentLoaded", async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const domain = urlParams.get("domain");

    if (!domain) return;

    const domainTitle = document.getElementById("inspector-domain");
    if (domainTitle) {
        domainTitle.textContent = domain;
    }

    document.getElementById("reload")?.addEventListener("click", async () => {
        const tabs = await browser.tabs.query({});
        const targetTab = tabs.find(tab => {
            try {
                const u = new URL(tab.url);
                return u.hostname === domain || u.hostname.endsWith('.' + domain);
            } catch (e) { return false; }
        });

        if (targetTab) {
            await browser.tabs.reload(targetTab.id);
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } else {
            window.location.reload();
        }
    });

    const rdapData = typeof getFullDomainDetails === "function" ? await getFullDomainDetails(domain) : null;
    if (rdapData) {
        document.getElementById("rdap-registrar").textContent = rdapData.registrar || "Unknown";
        document.getElementById("rdap-abuse").textContent = rdapData.abuseEmail || "Unknown";
        document.getElementById("rdap-created").textContent = rdapData.createdAt || "N/A";
        document.getElementById("rdap-updated").textContent = rdapData.updatedAt || "N/A";
        document.getElementById("rdap-expires").textContent = rdapData.expiresAt || "N/A";
        document.getElementById("rdap-owner").textContent = rdapData.owner || "Unknown";

        const nsContainer = document.getElementById("rdap-nameservers");
        if (nsContainer) {
            if (rdapData.nameServers && rdapData.nameServers.length > 0) {
                nsContainer.innerHTML = rdapData.nameServers.map(ns => `<li>${escapeHtml(ns)}</li>`).join('');
            } else {
                nsContainer.innerHTML = `<li>No NameServer found</li>`;
            }
        }

        const statusContainer = document.getElementById("rdap-status");
        if (statusContainer) {
            if (rdapData.statusCodes && rdapData.statusCodes.length > 0) {
                statusContainer.innerHTML = rdapData.statusCodes.map(st => `<li style="color: var(--accent-blue);">${escapeHtml(st)}</li>`).join('');
            } else {
                statusContainer.innerHTML = `<li>No status data provided</li>`;
            }
        }
    } else {
        document.getElementById("rdap-registrar").textContent = "Unknown";
        document.getElementById("rdap-abuse").textContent = "Unknown";
        document.getElementById("rdap-created").textContent = "N/A";
        document.getElementById("rdap-updated").textContent = "N/A";
        document.getElementById("rdap-expires").textContent = "N/A";
        document.getElementById("rdap-owner").textContent = "Unknown";
    }

    let response = null;
    try {
        response = await browser.runtime.sendMessage({
            action: "getDomainInspectorData",
            domain: domain
        });
    } catch (error) {
        console.error("[CookieJar] Connection error:", error);
    }

    if (response) {
        document.getElementById("net-ip").textContent = response.ip || "N/A";
        document.getElementById("net-protocol").textContent = response.protocol || "N/A";
        document.getElementById("net-requests").textContent = response.requestsCount || 0;

        const extList = document.getElementById("external-domains-list");
        const extDomains = response.externalDomains || [];
        document.getElementById("ext-count").textContent = extDomains.length.toString();

        if (extList) {
            if (extDomains.length > 0) {
                extList.innerHTML = extDomains.map(d => `<li>${escapeHtml(d)}</li>`).join('');
            } else {
                extList.innerHTML = `<li>No external domains found</li>`;
            }
        }

        const wsList = document.getElementById("websocket-list");
        const webSockets = response.webSockets || [];
        document.getElementById("ws-count").textContent = webSockets.length.toString();

        if (wsList) {
            if (webSockets.length > 0) {
                wsList.innerHTML = webSockets.map(ws => `<li style="color: var(--accent-orange);">${escapeHtml(ws)}</li>`).join('');
            } else {
                wsList.innerHTML = `<li>No active connections</li>`;
            }
        }

        if (response.ip && response.ip !== "N/A" && response.ip !== "Unknown" && response.ip !== "127.0.0.1") {
            const ipData = await getGeoLocation(response.ip);
            const fields = ["country", "region", "city", "latitude", "longitude", "offset", "isp", "reverse", "proxy", "mobile", "hosting"];

            fields.forEach(field => {
                const el = document.getElementById(`ip-${field}`);
                if (el) {
                    el.textContent = ipData[field] !== undefined ? ipData[field] : "N/A";
                }
            });
        }

        const secList = document.getElementById("security-headers");
        if (secList) {
            if (response.securityHeaders) {
                const h = response.securityHeaders;
                secList.innerHTML = `
                    <li>Strict-Transport-Security (HSTS): ${renderBadge(h.hsts)}</li>
                    <li>Content-Security-Policy (CSP): ${renderBadge(h.csp)}</li>
                    <li>X-Content-Type-Options (nosniff): ${renderBadge(h.xcontent)}</li>
                    <li>X-Frame-Options: <strong>${escapeHtml(h.xframe || "Not set")}</strong></li>
                    <li>Referrer-Policy: <strong>${escapeHtml(h.referrerPolicy || "Not set")}</strong></li>
                `;
            } else {
                secList.innerHTML = `<li>Data not found.</li>`;
            }
        }
    }
});

async function getGeoLocation(ip) {
    try {
        const response = await fetch(`https://ipwho.is/${ip}`);
        if (!response.ok) throw new Error("Network response was not ok");

        const data = await response.json();
        if (!data.success) throw new Error(data.message || "IP lookup failed");

        return {
            country: data.country || "Unknown",
            region: data.region || "Unknown",
            city: data.city || "Unknown",
            latitude: data.latitude || "N/A",
            longitude: data.longitude || "N/A",
            offset: data.timezone?.utc || "N/A",
            isp: data.connection?.isp || "Unknown",
            reverse: data.connection?.domain || "Unknown",
            proxy: data.security?.proxy || false,
            mobile: data.type === "Mobile",
            hosting: data.security?.hosting || false,
        };
    } catch (e) {
        console.warn("[CookieJar] Geolocation fetch error:", e);
        return {
            country: "Unknown",
            region: "Unknown",
            city: "Unknown",
            latitude: "N/A",
            longitude: "N/A",
            offset: "N/A",
            isp: "Unknown",
            reverse: "Unknown",
            proxy: false,
            mobile: false,
            hosting: false,
        };
    }
}

function renderBadge(active) {
    return active
        ? `<span style="color: #a6e3a1; font-weight: normal;">✔</span>`
        : `<span style="color: #f38ba8; font-weight: normal;">✘</span>`;
}