document.addEventListener("DOMContentLoaded", async () => {
    const content = document.getElementById("content");
    const searchInput = document.getElementById("search-input");
    const scopeSelect = document.getElementById("storage-scope");

    let currentItems = [];
    let currentDomain = "";
    let activeTabId = null;

    try {
        const urlParams = new URLSearchParams(window.location.search);
        currentDomain = urlParams.get("domain");

        const [tab] = await browser.tabs.query({ active: true, currentWindow: false });
        if (tab) activeTabId = tab.id;

        if (!currentDomain) {
            content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted);">No valid domain found.</div>`;
            return;
        }

        await loadScopeData();
    } catch (e) {
        console.error(e);
        content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--accent-red);">Error loading storage data.</div>`;
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
                case "cookies":
                    const cookies = await browser.cookies.getAll({ domain: currentDomain });
                    currentItems = cookies.map(c => ({ key: c.name, value: c.value, raw: c }));
                    break;

                case "localStorage":
                case "sessionStorage":
                    currentItems = await getWebStorageItems(scope);
                    break;

                case "extensionStorage":
                    const extData = await browser.storage.local.get(null);
                    currentItems = Object.entries(extData).map(([k, v]) => ({
                        key: k,
                        value: typeof v === "object" ? JSON.stringify(v) : String(v),
                        raw: v
                    }));
                    break;
            }
            renderList(currentItems);
        } catch (err) {
            console.error(err);
            content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--accent-red);">Failed to read ${scope}.</div>`;
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
            content.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted);">No entries found.</div>`;
            return;
        }

        const list = document.createElement("div");

        itemsToRender.forEach(item => {
            const card = document.createElement("div");
            card.className = "storage-item";

            const info = document.createElement("div");
            info.className = "storage-info";

            const updateDisplay = (val) => {
                info.innerHTML = `<strong>${escapeHtml(item.key)}</strong>: <span style="color: var(--accent-blue);">${escapeHtml(val)}</span>`;
            };
            updateDisplay(item.value);

            const actions = document.createElement("div");
            actions.className = "actions-container";

            const editBtn = document.createElement("button");
            editBtn.className = "btn-action edit";
            editBtn.innerHTML = `<i class="fa-solid fa-pen"></i>`;

            const deleteBtn = document.createElement("button");
            deleteBtn.className = "btn-action delete";
            deleteBtn.innerHTML = `<i class="fa-solid fa-trash-can"></i>`;

            editBtn.addEventListener("click", () => {
                const textarea = document.createElement("textarea");
                textarea.value = item.value;
                textarea.style.cssText = "width:100%; min-height:50px; resize:vertical; background:var(--bg-input, #45475a); color:var(--text-main); border:1px solid #585b70; border-radius:4px; padding:6px; box-sizing:border-box;";

                info.innerHTML = `<strong>${escapeHtml(item.key)}</strong><br>`;
                info.appendChild(textarea);

                editBtn.style.display = "none";
                const saveBtn = document.createElement("button");
                saveBtn.className = "btn-action save";
                saveBtn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i>`;
                actions.prepend(saveBtn);

                saveBtn.addEventListener("click", async () => {
                    const newValue = textarea.value;
                    const scope = scopeSelect.value;

                    if (scope === "cookies") {
                        const c = item.raw;
                        const protocol = c.secure ? "https://" : "http://";
                        const url = `${protocol}${c.domain.startsWith('.') ? c.domain.substring(1) : c.domain}${c.path}`;
                        await browser.cookies.set({ url, name: c.name, value: newValue, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, expirationDate: c.expirationDate });
                    }
                    else if (scope === "localStorage" || scope === "sessionStorage") {
                        await browser.scripting.executeScript({
                            target: { tabId: activeTabId },
                            func: (type, k, v) => window[type].setItem(k, v),
                            args: [scope, item.key, newValue]
                        });
                    }
                    else if (scope === "extensionStorage") {
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
                const scope = scopeSelect.value;

                if (scope === "cookies") {
                    const c = item.raw;
                    const protocol = c.secure ? "https://" : "http://";
                    const url = `${protocol}${c.domain.startsWith('.') ? c.domain.substring(1) : c.domain}${c.path}`;
                    await browser.cookies.remove({ url, name: c.name, storeId: c.storeId });
                }
                else if (scope === "localStorage" || scope === "sessionStorage") {
                    await browser.scripting.executeScript({
                        target: { tabId: activeTabId },
                        func: (type, k) => window[type].removeItem(k),
                        args: [scope, item.key]
                    });
                }
                else if (scope === "extensionStorage") {
                    await browser.storage.local.remove(item.key);
                }

                currentItems = currentItems.filter(i => i.key !== item.key);
                renderList(currentItems.filter(i => i.key.toLowerCase().includes(searchInput.value.toLowerCase())));
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

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}