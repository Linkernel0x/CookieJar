document.addEventListener("DOMContentLoaded", async () => {
    document.getElementById("open-dashboard")?.addEventListener("click", () => {
        window.location.href = "index.html";
    });

    document.getElementById("wipe")?.addEventListener("click", async () => {
        if (window.confirm("Are you sure you want to permanently reset the database? This cannot be undone.")) {
            await browser.storage.local.clear();
            window.alert("Database cleared successfully!");
            window.location.reload();
        }
    });

    const data = await browser.storage.local.get("CookieJar");
    await loadMisc(data);
    await loadTrustSettings(data);
});

async function loadMisc(data) {
    const profile = Profile.fromJSON(data.CookieJar);
    const miscContainer = document.getElementById("misc-settings");
    if (!miscContainer) return;

    miscContainer.innerHTML = "";

    Object.entries(profile.settings.misc).forEach(([key, value]) => {
        const row = document.createElement("div");
        row.className = "setting-card";

        const label = document.createElement("label");
        label.style.display = "flex";
        label.style.alignItems = "center";
        label.style.gap = "8px";
        label.style.cursor = "pointer";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.id = `setting-${key}`;
        checkbox.checked = !!value;

        const textNode = document.createTextNode(key);

        label.appendChild(checkbox);
        label.appendChild(textNode);
        row.appendChild(label);
        miscContainer.appendChild(row);

        checkbox.addEventListener("change", async (e) => {
            profile.settings.misc[key] = e.target.checked;
            await browser.storage.local.set({ CookieJar: profile.toJSON() });
        });
    });
}

async function loadTrustSettings(data) {
    const profile = Profile.fromJSON(data.CookieJar);
    const trustContainer = document.getElementById("trust-settings");
    if (!trustContainer) return;

    trustContainer.innerHTML = "";

    Object.entries(profile.settings.trust).forEach(([key, value]) => {
        const row = document.createElement("div");
        row.className = "setting-card";

        const title = document.createElement("b");
        title.textContent = key;
        title.style.display = "block";
        title.style.marginBottom = "8px";
        title.style.color = "var(--accent-blue)";

        const labelEnabled = document.createElement("label");
        labelEnabled.style.display = "flex";
        labelEnabled.style.alignItems = "center";
        labelEnabled.style.gap = "8px";
        labelEnabled.style.marginBottom = "8px";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = !!value.enabled;

        labelEnabled.appendChild(checkbox);
        labelEnabled.appendChild(document.createTextNode("Enabled"));

        row.appendChild(title);
        row.appendChild(labelEnabled);

        if (value.apiKey !== undefined) {
            const inputLabel = document.createElement("label");
            inputLabel.textContent = "API Key:";
            inputLabel.style.fontSize = "0.9rem";

            const inputField = document.createElement("input");
            inputField.type = "text";
            inputField.value = value.apiKey;
            inputField.placeholder = "Enter API Key...";

            inputLabel.appendChild(inputField);
            row.appendChild(inputLabel);

            inputField.addEventListener("change", async (e) => {
                profile.settings.trust[key].apiKey = e.target.value;
                await browser.storage.local.set({CookieJar: profile.toJSON()});
            });
        }

        trustContainer.appendChild(row);

        checkbox.addEventListener("change", async (e) => {
            profile.settings.trust[key].enabled = e.target.checked;
            await browser.storage.local.set({ CookieJar: profile.toJSON() });
        });
    });
}