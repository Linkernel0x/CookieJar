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

    document.getElementById("export")?.addEventListener("click", async () => {
        const data = await browser.storage.local.get("CookieJar");
        const blob = new Blob([JSON.stringify(data.CookieJar, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob)
        browser.tabs.create({ url: url });
    });

    document.getElementById("import")?.addEventListener("click", async () => {
        const fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.accept = ".json,application/json";
        fileInput.addEventListener("change", async (event) => {
            const file = event.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    const importedData = JSON.parse(e.target.result);
                    if (!importedData || typeof importedData !== "object") throw new Error("Invalid JSON structure.");
                    await browser.storage.local.set({ CookieJar: importedData });
                    window.alert("Import successful!");
                    window.location.reload();
                } catch (error) {
                    console.error("Error importing data:", error);
                    window.alert("Failed to import data. Please ensure the JSON structure is correct.");
                }
            };
            reader.readAsText(file);
        });
        fileInput.click();
    });

    const data = await browser.storage.local.get("CookieJar") || {};
    await loadMisc(data);
    await loadTrustSettings(data);
    await loadVirusTotalSettings(data);
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

        if (typeof value === "boolean") {
            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.id = `setting-${key}`;
            checkbox.checked = !!value;

            label.appendChild(checkbox);

            checkbox.addEventListener("change", async (e) => {
                profile.settings.misc[key] = e.target.checked;
                await browser.storage.local.set({CookieJar: profile.toJSON()});
            });
        } else if (typeof value === "number") {
            const numberInput = document.createElement("input");
            numberInput.type = "number";
            numberInput.id = `setting-${key}`;
            numberInput.min = "-1"
            numberInput.value = value ?? -1;

            label.appendChild(numberInput);

            numberInput.addEventListener("change", async (e) => {
                profile.settings.misc[key] = parseInt(e.target.value, 10);
                await browser.storage.local.set({CookieJar: profile.toJSON()});
            });
        }

        const textNode = document.createTextNode(key);
        label.appendChild(textNode);
        row.appendChild(label);
        miscContainer.appendChild(row);

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

async function loadVirusTotalSettings(data) {
    const profile = Profile.fromJSON(data.CookieJar);
    const vtContainer = document.getElementById("virustotal-settings");
    if (!vtContainer) return;

    vtContainer.innerHTML = "";
    const vtSettings = profile.settings.virustotal;

    const globalCard = document.createElement("div");
    globalCard.className = "setting-card";

    const globalTitle = document.createElement("b");
    globalTitle.textContent = "Global Settings";
    globalTitle.style.display = "block";
    globalTitle.style.marginBottom = "8px";
    globalTitle.style.color = "var(--accent-blue)";

    const globalLabel = document.createElement("label");
    globalLabel.textContent = "Global API Key (Fallback):";
    globalLabel.style.fontSize = "0.9rem";

    const globalInput = document.createElement("input");
    globalInput.type = "text";
    globalInput.value = vtSettings.globalApiKey || "";
    globalInput.placeholder = "Enter main VirusTotal Key...";

    globalLabel.appendChild(globalInput);
    globalCard.appendChild(globalTitle);
    globalCard.appendChild(globalLabel);
    vtContainer.appendChild(globalCard);

    globalInput.addEventListener("change", async (e) => {
        profile.settings.virustotal.globalApiKey = e.target.value.trim();
        await browser.storage.local.set({ CookieJar: profile.toJSON() });
    });

    const trustCard = createVtSubCard("Trust Level Evaluation", vtSettings.trustLevel, async (updatedData) => {
        profile.settings.virustotal.trustLevel = updatedData;
        await browser.storage.local.set({ CookieJar: profile.toJSON() });
    });
    vtContainer.appendChild(trustCard);

    const downloadCard = createVtSubCard("Download Protection", vtSettings.downloadScan, async (updatedData) => {
        profile.settings.virustotal.downloadScan = updatedData;
        await browser.storage.local.set({ CookieJar: profile.toJSON() });
    }, true);

    vtContainer.appendChild(downloadCard);
}

function createVtSubCard(titleText, configObj, saveCallback, includeMinResults = false) {
    const card = document.createElement("div");
    card.className = "setting-card";

    const title = document.createElement("b");
    title.textContent = titleText;
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
    checkbox.checked = !!configObj.enabled;

    labelEnabled.appendChild(checkbox);
    labelEnabled.appendChild(document.createTextNode("Enabled"));

    const keyLabel = document.createElement("label");
    keyLabel.textContent = "Dedicated API Key (Optional):";
    keyLabel.style.fontSize = "0.9rem";

    const keyInput = document.createElement("input");
    keyInput.type = "text";
    keyInput.value = configObj.apiKey || "";
    keyInput.placeholder = "Leave empty to use Global Key...";

    keyLabel.appendChild(keyInput);

    card.appendChild(title);
    card.appendChild(labelEnabled);
    card.appendChild(keyLabel);

    if (includeMinResults) {
        const minLabel = document.createElement("label");
        minLabel.textContent = "Min Malicious Engines to Block:";
        minLabel.style.fontSize = "0.9rem";
        minLabel.style.marginTop = "8px";

        const minInput = document.createElement("input");
        minInput.type = "number";
        minInput.min = "1";
        minInput.value = configObj.minimumResults ?? 1;

        minLabel.appendChild(minInput);
        card.appendChild(minLabel);

        minInput.addEventListener("change", (e) => {
            configObj.minimumResults = parseInt(e.target.value, 10) || 1;
            saveCallback(configObj);
        });
    }

    checkbox.addEventListener("change", (e) => {
        configObj.enabled = e.target.checked;
        saveCallback(configObj);
    });

    keyInput.addEventListener("change", (e) => {
        configObj.apiKey = e.target.value.trim();
        saveCallback(configObj);
    });

    return card;
}