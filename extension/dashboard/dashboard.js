let currentExplorerItems = [];
let profile = null;

document.addEventListener("DOMContentLoaded", async () => {
    const storage = await browser.storage.local.get("CookieJar");
    profile = Profile.fromJSON(storage.CookieJar);

    document.getElementById("open-settings")?.addEventListener("click", () => {
        window.location.href = "settings.html";
    });

    const graph1 = document.getElementById('trust-history-chart');
    await renderTrustGraph(graph1, profile.trustPoints || {});
    await renderTrustHighlights(profile);
    await renderHistoryTable(profile);

    await initStorageExplorer();
    await initListManager();
});

async function renderTrustGraph(graph, trustPoints = {}) {
    let blue_sites = 0, green_sites = 0, yellow_sites = 0, red_sites = 0;

    for (const [key, value] of Object.entries(trustPoints)) {
        if (!value || typeof value.score !== "number") continue;
        if (value.score === 100) blue_sites++;
        else if (value.score > 70) green_sites++;
        else if (value.score > 35) yellow_sites++;
        else red_sites++;
    }

    const total = blue_sites + green_sites + yellow_sites + red_sites;
    const dangerousElem = document.getElementById('dangerous-total');
    if (dangerousElem) dangerousElem.innerText = `${red_sites + yellow_sites} (${red_sites} critical)`;

    const totalElem = document.getElementById('trust-total');
    if (totalElem) totalElem.innerText = total.toString();

    const totalLabelElem = document.getElementById('trust-total-label');
    if (totalLabelElem) totalLabelElem.innerText = total.toString();

    const segments = {
        blue: document.getElementById('segment-blue'),
        green: document.getElementById('segment-green'),
        yellow: document.getElementById('segment-yellow'),
        red: document.getElementById('segment-red')
    };

    if (total === 0) {
        Object.values(segments).forEach(seg => { if (seg) seg.style.strokeDasharray = "0 100"; });
        return;
    }

    const bluePct = (blue_sites / total) * 100;
    const greenPct = (green_sites / total) * 100;
    const yellowPct = (yellow_sites / total) * 100;
    const redPct = (red_sites / total) * 100;

    if (segments.blue) { segments.blue.style.strokeDasharray = `${bluePct} ${100 - bluePct}`; segments.blue.style.strokeDashoffset = "0"; }
    if (segments.green) { segments.green.style.strokeDasharray = `${greenPct} ${100 - greenPct}`; segments.green.style.strokeDashoffset = `-${bluePct}`; }
    if (segments.yellow) { segments.yellow.style.strokeDasharray = `${yellowPct} ${100 - yellowPct}`; segments.yellow.style.strokeDashoffset = `-${bluePct + greenPct}`; }
    if (segments.red) { segments.red.style.strokeDasharray = `${redPct} ${100 - redPct}`; segments.red.style.strokeDashoffset = `-${bluePct + greenPct + yellowPct}`; }
}

async function renderTrustHighlights(profile) {
    const sources = document.getElementById('sources');
    const scoreTag = document.getElementById('score-tag');
    const siteTag = document.getElementById('site');
    const enabled_modules = document.getElementById('enabled-modules');

    if (enabled_modules && profile.settings?.trust) {
        enabled_modules.innerHTML = "";
        for (let [key, options] of Object.entries(profile.settings.trust)) {
            if (options.enabled) {
                const li = document.createElement("li");
                li.textContent = options.apiKey ? `${key} (${options.apiKey})` : key;
                enabled_modules.appendChild(li);
            }
        }
    }

    const trustEntries = Object.entries(profile.trustPoints || {});

    if (trustEntries.length === 0) {
        if (scoreTag) scoreTag.textContent = "N/A";
        if (siteTag) siteTag.textContent = "No sites visited yet";
        if (sources) sources.innerHTML = "<li>No analyzed sites found.</li>";
        return;
    }

    trustEntries.sort((a, b) => a[1].score - b[1].score);
    const [worstDomain, worstData] = trustEntries[0];

    if (scoreTag) {
        scoreTag.textContent = worstData.score.toString();
        scoreTag.style.background = worstData.score <= 35 ? "var(--accent-red)" : worstData.score <= 65 ? "var(--accent-orange)" : "var(--accent-green)";
        scoreTag.style.color = "#11111b";
    }

    if (siteTag) siteTag.textContent = worstDomain;

    const formattedTime = worstData.timestamp ? new Date(worstData.timestamp).toLocaleString() : "Unknown";

    if (sources && worstData.sources) {
        sources.innerHTML = `
        <li>Google: <span style="float: right">${renderStatus(worstData.sources.googleSafeBrowsing, "boolean")}</span></li>
        <li>Alien Vault: <span style="float: right">${renderStatus(worstData.sources.alienVaultOTX, "count")} pulses</span></li>
        <li>PhishTank: <span style="float: right">${renderStatus(worstData.sources.phishTank, "boolean")}</span></li>
        <li>URLScan: <span style="float: right">${renderStatus(worstData.sources.urlScan, "boolean")}</span></li>
        <li>OpenPhish: <span style="float: right">${renderStatus(worstData.sources.openPhish, "boolean")}</span></li>
        <li>Tranco Rank: <span style="float: right">${renderStatus(worstData.sources.trancoRank, "text")}</span></li>
        <li>Domain Age: <span style="float: right">${renderStatus(worstData.sources.domainAgeDays, "days")}</span></li>
        <li>VirusTotal: <span style="float: right">${renderStatus(worstData.sources.virusTotal, "count")}</span></li>
        <li style="margin-top: 8px; font-style: italic; color: #a6adc8;">Analysed: ${formattedTime}</li>
        `;
    }
}

async function renderHistoryTable(profile) {
    const historyContainer = document.getElementById('trust-history-list');
    if (!historyContainer) return;

    const trustEntries = Object.entries(profile.trustPoints || {});

    if (trustEntries.length === 0) {
        historyContainer.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 16px;">No history recorded yet.</div>`;
        return;
    }

    trustEntries.sort((a, b) => (b[1].timestamp || 0) - (a[1].timestamp || 0));

    historyContainer.innerHTML = trustEntries.map(([domain, data]) => {
        let badgeColor = data.score <= 35 ? "var(--accent-red)" : data.score <= 65 ? "var(--accent-orange)" : "var(--accent-green)";
        let badgeBg = data.score <= 35 ? "rgba(243, 139, 168, 0.15)" : data.score <= 65 ? "rgba(250, 179, 135, 0.15)" : "rgba(166, 227, 161, 0.15)";
        const dateStr = data.timestamp ? new Date(data.timestamp).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : 'Unknown';
        const sources = data.sources || {};

        return `
            <div class="history-item">
                <div class="history-info">
                    <details>
                        <summary><span class="history-domain">${domain}</span></summary>
                        <ul style="padding-left: 16px; margin-top: 8px; font-size: 0.85rem;">
                            <li>Google: <span style="float: right">${renderStatus(sources.googleSafeBrowsing, "boolean")}</span></li>
                            <li>Alien Vault: <span style="float: right">${renderStatus(sources.alienVaultOTX, "count")} pulses</span></li>
                            <li>PhishTank: <span style="float: right">${renderStatus(sources.phishTank, "boolean")}</span></li>
                            <li>URLScan: <span style="float: right">${renderStatus(sources.urlScan, "boolean")}</span></li>
                            <li>OpenPhish: <span style="float: right">${renderStatus(sources.openPhish, "boolean")}</span></li>
                            <li>Tranco Rank: <span style="float: right">${renderStatus(sources.trancoRank, "text")}</span></li>
                            <li>Domain Age: <span style="float: right">${renderStatus(sources.domainAgeDays, "days")}</span></li>
                            <li>VirusTotal: <span style="float: right">${renderStatus(sources.virusTotal, "count")}</span></li>
                        </ul>
                    </details>
                    <span class="history-date"><i class="fa-regular fa-clock"></i> ${dateStr}</span>
                </div>
                <div class="history-score" style="color: ${badgeColor}; background: ${badgeBg}; border: 1px solid ${badgeColor}40;">
                    ${data.score} / 100
                </div>
            </div>
        `;
    }).join('');
}

//
async function initStorageExplorer() {
    const domainSelect = document.getElementById("domain-select");
    const scopeSelect = document.getElementById("scope-select");
    const searchInput = document.getElementById("explorer-search");

    if (!domainSelect || !scopeSelect) return;

    const cookies = await browser.cookies.getAll({});
    const domainsSet = new Set();

    cookies.forEach(c => {
        const cleanDomain = c.domain.startsWith('.') ? c.domain.substring(1) : c.domain;
        domainsSet.add(cleanDomain);
    });

    if (profile?.frozenCookies) {
        Object.values(profile.frozenCookies).forEach(f => {
            domainsSet.add(f.domain);
        });
    }

    const domains = Array.from(domainsSet).sort();

    if (domains.length === 0) {
        domainSelect.innerHTML = `<option value="">No domain found</option>`;
        return;
    }

    domainSelect.innerHTML = domains.map(d => `<option value="${d}">${d}</option>`).join('');

    domainSelect.addEventListener("change", updateExplorer);
    scopeSelect.addEventListener("change", updateExplorer);
    searchInput?.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase();
        renderExplorerList(currentExplorerItems.filter(i => i.key.toLowerCase().includes(query)));
    });

    await updateExplorer();
}

async function updateExplorer() {
    const domainSelect = document.getElementById("domain-select");
    const scopeSelect = document.getElementById("scope-select");
    const listContainer = document.getElementById("storage-explorer-list");

    const domain = domainSelect.value;
    const scope = scopeSelect.value;

    if (!domain) return;

    listContainer.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 20px;">Caricamento ${scope}...</div>`;

    try {
        if (scope === "cookies") {
            const cookies = await browser.cookies.getAll({ domain: domain });
            const activeItems = cookies.map(c => ({
                key: c.name,
                value: c.value,
                isFrozen: false,
                raw: c
            }));
            const frozenItems = getFrozenCookies(profile, domain);

            currentExplorerItems = [...activeItems, ...frozenItems];
        } else {
            const tabs = await browser.tabs.query({});
            const targetTab = tabs.find(tab => {
                try {
                    const u = new URL(tab.url);
                    return u.hostname === domain || u.hostname.endsWith('.' + domain);
                } catch (e) { return false; }
            });

            if (!targetTab) {
                listContainer.innerHTML = `
                    <div style="text-align: center; padding: 20px; color: var(--text-muted);">
                        <p>No open tab found for <strong>${escapeHtml(domain)}</strong>.</p>
                        <p style="font-size: 0.85rem; margin-top: 8px;">To access ${scope}, open the domain in a new tab</p>
                        <button class="btn primary" id="open-tab-btn" style="margin-top: 12px;">Open ${domain}</button>
                    </div>
                `;
                document.getElementById("open-tab-btn")?.addEventListener("click", () => {
                    browser.tabs.create({ url: `https://${domain}` });
                });
                return;
            }

            const [{ result }] = await browser.scripting.executeScript({
                target: { tabId: targetTab.id },
                func: (storageType) => {
                    const store = window[storageType];
                    const items = [];
                    for (let i = 0; i < store.length; i++) {
                        const key = store.key(i);
                        items.push({ key, value: store.getItem(key) });
                    }
                    return items;
                },
                args: [scope]
            });
            currentExplorerItems = (result || []).map(i => ({ ...i, isFrozen: false }));
        }

        renderExplorerList(currentExplorerItems);
    } catch (err) {
        console.error(err);
        listContainer.innerHTML = `<div style="text-align: center; color: var(--accent-red); padding: 20px;">Errore nella lettura di ${scope}.</div>`;
    }
}

function renderExplorerList(itemsToRender) {
    const listContainer = document.getElementById("storage-explorer-list");
    listContainer.innerHTML = "";

    if (itemsToRender.length === 0) {
        listContainer.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 20px;">Nessun elemento trovato.</div>`;
        return;
    }

    const domainSelect = document.getElementById("domain-select");
    const scopeSelect = document.getElementById("scope-select");

    itemsToRender.forEach(item => {
        const itemEl = document.createElement("div");
        itemEl.className = "history-item";

        if (item.isFrozen) {
            itemEl.style.opacity = "0.8";
            itemEl.style.borderLeft = "4px solid var(--accent-blue)";
        }

        const info = document.createElement("div");
        info.className = "history-info";
        info.style.cssText = "overflow: hidden; text-overflow: ellipsis; max-width: 60%;";

        const updateDisplay = (val) => {
            info.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="history-domain">${escapeHtml(item.key)}</span>
                    ${item.isFrozen ? '<span class="text-tag" style="background: var(--accent-blue); color: #11111b; font-size: 0.7rem;">FROZEN</span>' : ''}
                </div>
                <span style="font-size: 0.85rem; color: var(--accent-blue); word-break: break-all;">${escapeHtml(val)}</span>
            `;
        };
        updateDisplay(item.value);

        const actions = document.createElement("div");
        actions.style.cssText = "display: flex; gap: 6px; align-items: center;";

        if (scopeSelect.value === "cookies") {
            const freezeBtn = document.createElement("button");
            freezeBtn.className = `btn ${item.isFrozen ? 'primary' : 'secondary'}`;
            freezeBtn.style.cssText = "padding: 6px 10px; font-size: 0.8rem;";
            freezeBtn.innerHTML = `<i class="fa-solid ${item.isFrozen ? 'fa-snowflake' : 'fa-snowflake'}"></i> `;

            freezeBtn.addEventListener("click", async () => {
                if (item.isFrozen) {
                    await unfreezeCookie(profile, item.freezeId);
                } else {
                    await freezeCookie(profile, item.raw);
                }
                await updateExplorer();
            });
            actions.appendChild(freezeBtn);
        }

        const editBtn = document.createElement("button");
        editBtn.className = "btn primary";
        editBtn.style.cssText = "padding: 6px 10px; font-size: 0.8rem;";
        editBtn.innerHTML = `<i class="fa-solid fa-pen"></i>`;

        const deleteBtn = document.createElement("button");
        deleteBtn.className = "btn crucial";
        deleteBtn.style.cssText = "padding: 6px 10px; font-size: 0.8rem;";
        deleteBtn.innerHTML = `<i class="fa-solid fa-trash-can"></i>`;

        editBtn.addEventListener("click", () => {
            const textarea = document.createElement("textarea");
            textarea.value = item.value;
            textarea.style.cssText = "width:100%; min-height:50px; resize:vertical; background:var(--bg-input); color:var(--text-main); border:1px solid #585b70; border-radius:4px; padding:6px; box-sizing:border-box; margin-top:4px;";

            info.innerHTML = `<strong>${escapeHtml(item.key)}</strong>`;
            info.appendChild(textarea);

            editBtn.style.display = "none";
            const saveBtn = document.createElement("button");
            saveBtn.className = "btn primary";
            saveBtn.style.cssText = "padding: 6px 10px; font-size: 0.8rem;";
            saveBtn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i>`;
            actions.insertBefore(saveBtn, deleteBtn);

            saveBtn.addEventListener("click", async () => {
                const newValue = textarea.value;
                const scope = scopeSelect.value;
                const domain = domainSelect.value;

                if (scope === "cookies") {
                    if (item.isFrozen) {
                        profile.frozenCookies[item.freezeId].originalCookie.value = newValue;
                        await browser.storage.local.set({ CookieJar: profile.toJSON() });
                    } else {
                        const c = item.raw;
                        const protocol = c.secure ? "https://" : "http://";
                        const url = `${protocol}${c.domain.startsWith('.') ? c.domain.substring(1) : c.domain}${c.path}`;
                        await browser.cookies.set({
                            url,
                            name: c.name,
                            value: newValue,
                            domain: c.domain,
                            path: c.path,
                            secure: c.secure,
                            httpOnly: c.httpOnly,
                            sameSite: c.sameSite,
                            expirationDate: c.expirationDate,
                            storeId: c.storeId
                        });
                    }
                } else if (scope === "localStorage" || scope === "sessionStorage") {
                    const tabs = await browser.tabs.query({});
                    const targetTab = tabs.find(t => t.url.includes(domain));
                    if (targetTab) {
                        await browser.scripting.executeScript({
                            target: { tabId: targetTab.id },
                            func: (type, k, v) => window[type].setItem(k, v),
                            args: [scope, item.key, newValue]
                        });
                    }
                }

                item.value = newValue;
                saveBtn.remove();
                editBtn.style.display = "inline-block";
                updateDisplay(item.value);
            });
        });

        deleteBtn.addEventListener("click", async () => {
            const scope = scopeSelect.value;
            const domain = domainSelect.value;

            if (scope === "cookies") {
                if (item.isFrozen) {
                    delete profile.frozenCookies[item.freezeId];
                    await browser.storage.local.set({ CookieJar: profile.toJSON() });
                } else {
                    const c = item.raw;
                    const protocol = c.secure ? "https://" : "http://";
                    const url = `${protocol}${c.domain.startsWith('.') ? c.domain.substring(1) : c.domain}${c.path}`;
                    await browser.cookies.remove({ url, name: c.name, storeId: c.storeId });
                }
            } else if (scope === "localStorage" || scope === "sessionStorage") {
                const tabs = await browser.tabs.query({});
                const targetTab = tabs.find(t => t.url.includes(domain));
                if (targetTab) {
                    await browser.scripting.executeScript({
                        target: { tabId: targetTab.id },
                        func: (type, k) => window[type].removeItem(k),
                        args: [scope, item.key]
                    });
                }
            }

            await updateExplorer();
        });

        actions.appendChild(editBtn);
        actions.appendChild(deleteBtn);
        itemEl.appendChild(info);
        itemEl.appendChild(actions);
        listContainer.appendChild(itemEl);
    });
}

async function initListManager() {
    const wlInput = document.getElementById("whitelist-input");
    const blInput = document.getElementById("blacklist-input");
    const wlBtn = document.getElementById("add-whitelist-btn");
    const blBtn = document.getElementById("add-blacklist-btn");

    if (!wlInput || !blInput) return;

    wlBtn?.addEventListener("click", async () => {
        await addDomainToList(wlInput.value, "whitelist");
        wlInput.value = "";
    });

    blBtn?.addEventListener("click", async () => {
        await addDomainToList(blInput.value, "blacklist");
        blInput.value = "";
    });

    renderLists();
}

async function addDomainToList(domain, listType) {
    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!cleanDomain) return;

    if (!profile.settings.lists) {
        profile.settings.lists = { whitelist: [], blacklist: [] };
    }

    const targetList = profile.settings.lists[listType];

    if (!targetList.includes(cleanDomain)) {
        targetList.push(cleanDomain);
        const oppositeType = listType === "whitelist" ? "blacklist" : "whitelist";

        profile.settings.lists[oppositeType] = profile.settings.lists[oppositeType].filter(d => d !== cleanDomain);

        if (profile.trustPoints[cleanDomain]) {
            delete profile.trustPoints[cleanDomain];
        }

        await browser.storage.local.set({ CookieJar: profile.toJSON() });
        renderLists();
    }
}

async function removeDomainFromList(domain, listType) {
    if (!profile.settings?.lists?.[listType]) return;

    profile.settings.lists[listType] = profile.settings.lists[listType].filter(d => d !== domain);
    await browser.storage.local.set({ CookieJar: profile.toJSON() });
    renderLists();
}

function renderLists() {
    const wlContainer = document.getElementById("whitelist-list");
    const blContainer = document.getElementById("blacklist-list");

    const lists = profile.settings?.lists || { whitelist: [], blacklist: [] };

    const populateContainer = (container, items, listType) => {
        if (!container) return;
        container.innerHTML = "";

        if (!items || items.length === 0) {
            container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 12px;">No domains added</div>`;
            return;
        }

        items.forEach(domain => {
            const itemEl = document.createElement("div");
            itemEl.className = "history-item";
            itemEl.style.padding = "8px 12px";

            const span = document.createElement("span");
            span.className = "history-domain";
            span.textContent = domain;

            const deleteBtn = document.createElement("button");
            deleteBtn.className = "btn crucial";
            deleteBtn.style.cssText = "padding: 4px 8px; font-size: 0.75rem;";
            deleteBtn.innerHTML = `<i class="fa-solid fa-trash-can"></i>`;

            deleteBtn.addEventListener("click", async () => {
                await removeDomainFromList(domain, listType);
            });

            itemEl.appendChild(span);
            itemEl.appendChild(deleteBtn);
            container.appendChild(itemEl);
        });
    };

    populateContainer(wlContainer, lists.whitelist, "whitelist");
    populateContainer(blContainer, lists.blacklist, "blacklist");
}