document.addEventListener("DOMContentLoaded", async () => {
    document.getElementById("open-dashboard")?.addEventListener("click", () => {
        window.location.href = "index.html";
    });

    document.getElementById("wipe")?.addEventListener("click", async () => {
        if (window.confirm("Are you sure you want to reset the database?")) {
            await browser.storage.local.clear();
            window.alert("Database cleared!");
            window.location.reload();
        }
    });

    const data = await browser.storage.local.get("CookieJar");
    await loadMisc(data);
    await loadTrustSettings(data);
});

async function loadMisc(data) {

    const profile = Profile.fromJSON(data.CookieJar);
    let miscContainer = document.getElementById("misc-settings");
    if (!miscContainer) return;

    miscContainer.innerHTML = "";

    Object.entries(profile.settings.misc).forEach(([key, value]) => {
        const row = document.createElement("div");
        row.style.margin = "8px 0";
        row.innerHTML = `
            <label>
                <input type="checkbox" id="setting-${key}" ${value ? "checked" : ""}>
                ${key}
            </label>
        `;
        miscContainer.appendChild(row);

        const checkbox = row.querySelector(`#setting-${key}`);
        checkbox.addEventListener("change", async (e) => {
            profile.settings.misc[key] = e.target.checked;
            await browser.storage.local.set({ CookieJar: profile.toJSON() });
        });
    });
}

async function loadTrustSettings(data) {

    const profile = Profile.fromJSON(data.CookieJar);
    let trustContainer = document.getElementById("trust-settings");
    if (!trustContainer) return;

    trustContainer.innerHTML = "";

    Object.entries(profile.settings.trust).forEach(([key, value]) => {
        const row = document.createElement("div");
        row.style.margin = "8px 0";
        if (value.apiKey !== undefined) {
            row.innerHTML = `
            <label>
                <b>${key}</b>
               
                <input type="checkbox" id="setting-${key}-enabled" ${value.enabled ? "checked" : ""}> Enabled <br/>
                API key <input type="text" id="setting-${key}-apikey" value="${value.apiKey}">
            </label>
        `;
        } else {
            row.innerHTML = `
            <label>
                <b>${key}</b>
                
                <input type="checkbox" id="setting-${key}-enabled" ${value.enabled ? "checked" : ""}>
            </label>
        `;
        }

        trustContainer.appendChild(row);

        const checkbox = row.querySelector(`#setting-${key}-enabled`);
        checkbox.addEventListener("change", async (e) => {
            profile.settings.trust[key].enabled = e.target.checked;
            await browser.storage.local.set({ CookieJar: profile.toJSON() });
        });
        if (value.apiKey) {
            const apiKey = row.querySelector(`#setting-${key}-apikey`);
            apiKey.addEventListener("change", async (e) => {
                profile.settings.trust[key].apiKey = e.target.value;
                await browser.storage.local.set({CookieJar: profile.toJSON()});
            });
        }
    });
}