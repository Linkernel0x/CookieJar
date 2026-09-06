document.addEventListener("DOMContentLoaded", async () => {
    const content = document.getElementById("content");
    const searchInput = document.getElementById("search-input");
    const scopeSelect = document.getElementById("storage-scope");

    let currentItems = [];
    let currentDomain = "";
    let activeTabId = null;
    let profile = null;

    try {
        const storage = await browser.storage.local.get("CookieJar");
        profile = Profile.fromJSON(storage.CookieJar);

        const urlParams = new URLSearchParams(window.location.search);
        currentDomain = urlParams.get("domain");

        const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
        if (tab) activeTabId = tab.id;

        if (!currentDomain && tab?.url) {
            try {
                const u = new URL(tab.url);
                currentDomain = u.hostname.startsWith('.') ? u.hostname.substring(1) : u.hostname;
            } catch (e) {}
        }

        if (!currentDomain) {
            content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted);">No valid domain found.</div>`;
            return;
        }

        await loadScopeData();
    } catch (e) {
        console.error(e);
        content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--accent-red);">Error while loading data.</div>`;
    }

    scopeSelect.addEventListener("change", async () => {
        searchInput.value = "";
        await loadScopeData();
    });

    async function loadScopeData() {
        const scope = scopeSelect.value;
        content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted);">Loading ${scope}...</div>`;

        try {
            switch (scope) {
                case "cookies": {
                    const cookies = await browser.cookies.getAll({ domain: currentDomain });
                    const activeItems = cookies.map(c => ({
                        key: c.name,
                        value: c.value,
                        isFrozen: false,
                        raw: c
                    }));
                    const frozenItems = getFrozenCookies(profile, currentDomain);
                    currentItems = [...activeItems, ...frozenItems];
                    break;
                }

                case "localStorage":
                case "sessionStorage": {
                    const webItems = await getWebStorageItems(scope);
                    currentItems = webItems.map(i => ({ ...i, isFrozen: false }));
                    break;
                }

                case "extensionStorage": {
                    const extData = await browser.storage.local.get(null);
                    currentItems = Object.entries(extData).map(([k, v]) => ({
                        key: k,
                        value: typeof v === "object" ? JSON.stringify(v) : String(v),
                        isFrozen: false,
                        raw: v
                    }));
                    break;
                }
            }
            renderList(currentItems);
        } catch (err) {
            console.error(err);
            content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--accent-red);">Could not read ${scope}. Open the dashboard to manage ${scope}.</div>`;
        }
    }

    async function getWebStorageItems(type) {
        if (!activeTabId) return [];
        const [{ result }] = await browser.scripting.executeScript({
            target: { tabId: activeTabId },
            func: (storageType) => {
                const store = window[storageType];
                const items = [];
                for (let i = 0; i < store.length; i++) {
                    const key = store.key(i);
                    items.push({ key, value: store.getItem(key) });
                }
                return items;
            },
            args: [type]
        });
        return result || [];
    }

    function renderList(itemsToRender) {
        content.innerHTML = "";
        if (itemsToRender.length === 0) {
            content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted);">No element found.</div>`;
            return;
        }

        const list = document.createElement("div");

        itemsToRender.forEach(item => {
            const card = document.createElement("div");
            card.className = "storage-item";

            if (item.isFrozen) {
                card.style.borderLeft = "3px solid var(--accent-blue)";
                card.style.opacity = "0.85";
            }

            const info = document.createElement("div");
            info.className = "storage-info";

            const updateDisplay = (val) => {
                info.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 2px;">
                        <strong>${escapeHtml(item.key)}</strong>
                        ${item.isFrozen ? '<span style="background: var(--accent-blue); color: #11111b; font-size: 0.65rem; padding: 1px 4px; border-radius: 4px; font-weight: bold;">FROZEN</span>' : ''}
                    </div>
                    <span style="color: var(--accent-blue);">${escapeHtml(val)}</span>
                `;
            };
            updateDisplay(item.value);

            const actions = document.createElement("div");
            actions.className = "actions-container";

            const scope = scopeSelect.value;

            if (scope === "cookies") {
                const freezeBtn = document.createElement("button");
                freezeBtn.className = "btn-action";
                freezeBtn.title = item.isFrozen ? "Unfreeze Cookie" : "Freeze Cookie";
                freezeBtn.style.color = "var(--accent-blue)";
                freezeBtn.innerHTML = `<i class="fa-solid fa-snowflake"></i>`;

                freezeBtn.addEventListener("click", async () => {
                    if (item.isFrozen) {
                        await unfreezeCookie(profile, item.freezeId);
                    } else {
                        await freezeCookie(profile, item.raw);
                    }
                    await loadScopeData();
                });
                actions.appendChild(freezeBtn);
            }

            const editBtn = document.createElement("button");
            editBtn.className = "btn-action edit";
            editBtn.title = "Edit";
            editBtn.innerHTML = `<i class="fa-solid fa-pen"></i>`;

            const deleteBtn = document.createElement("button");
            deleteBtn.className = "btn-action delete";
            deleteBtn.title = "Delete";
            deleteBtn.innerHTML = `<i class="fa-solid fa-trash-can"></i>`;

            editBtn.addEventListener("click", () => {
                const textarea = document.createElement("textarea");
                textarea.value = item.value;
                textarea.style.cssText = "width:100%; min-height:50px; resize:vertical; background:var(--bg-card); color:var(--text-main); border:1px solid #585b70; border-radius:4px; padding:6px; box-sizing:border-box; margin-top:4px;";

                info.innerHTML = `<strong>${escapeHtml(item.key)}</strong><br>`;
                info.appendChild(textarea);

                editBtn.style.display = "none";
                const saveBtn = document.createElement("button");
                saveBtn.className = "btn-action save";
                saveBtn.title = "Save";
                saveBtn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i>`;
                actions.insertBefore(saveBtn, deleteBtn);

                saveBtn.addEventListener("click", async () => {
                    const newValue = textarea.value;

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
                                expirationDate: c.expirationDate
                            });
                        }
                    } else if (scope === "localStorage" || scope === "sessionStorage") {
                        await browser.scripting.executeScript({
                            target: { tabId: activeTabId },
                            func: (type, k, v) => window[type].setItem(k, v),
                            args: [scope, item.key, newValue]
                        });
                    } else if (scope === "extensionStorage") {
                        let parsedVal = newValue;
                        try { parsedVal = JSON.parse(newValue); } catch (e) {}
                        await browser.storage.local.set({ [item.key]: parsedVal });
                    }

                    item.value = newValue;
                    saveBtn.remove();
                    editBtn.style.display = "inline-block";
                    updateDisplay(item.value);
                });
            });

            deleteBtn.addEventListener("click", async () => {
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
                    await browser.scripting.executeScript({
                        target: { tabId: activeTabId },
                        func: (type, k) => window[type].removeItem(k),
                        args: [scope, item.key]
                    });
                } else if (scope === "extensionStorage") {
                    await browser.storage.local.remove(item.key);
                }

                await loadScopeData();
            });

            actions.appendChild(editBtn);
            actions.appendChild(deleteBtn);
            card.appendChild(info);
            card.appendChild(actions);
            list.appendChild(card);
        });

        content.appendChild(list);
    }

    searchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase();
        renderList(currentItems.filter(i => i.key.toLowerCase().includes(query)));
    });

    document.getElementById("open-dashboard")?.addEventListener("click", () => {
        browser.tabs.create({ url: browser.runtime.getURL("dashboard/index.html") });
    });
});