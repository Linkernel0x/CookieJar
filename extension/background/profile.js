class Profile {
    constructor(schemaVersion = 1, trustPoints = {}, trustHistory = {}, settings = null, frozenCookies = {}) {
        this.schemaVersion = schemaVersion;
        this.trustPoints = trustPoints;
        this.trustHistory = trustHistory;
        this.settings = settings || {
            misc: { allowNotification: true,
                renderColorBadge: true,
                autoBlockMaliciousSites: -1 },
            trust: {
                googleSafeBrowsing: { apiKey: "", enabled: true },
                urlScan: { apiKey: "", enabled: true },
                AlienVaultOTX: { apiKey: "", enabled: true },
                trancoRank: { apiKey: "", enabled: true },
                phishTank: { apiKey: "", enabled: true }
            },
            virustotal: {
                globalApiKey: "",
                trustLevel: { enabled: false, apiKey: ""},
                downloadScan: { enabled: true, apiKey: "", minimumResults: 1}
            },
            lists: {
                whitelist: [],
                blacklist: []
            },
        };
        this.frozenCookies = frozenCookies || {};
    }

    static fromJSON(json) {
        if (!json) return new Profile();
        return new Profile(json.schemaVersion ?? 1, json.trustPoints ?? {}, json.trustHistory ?? {}, json.settings ?? new Profile().settings, json.frozenCookies ?? {});
    }

    toJSON() {
        return {
            schemaVersion: this.schemaVersion,
            trustPoints: this.trustPoints,
            trustHistory: this.trustHistory,
            settings: this.settings,
            frozenCookies: this.frozenCookies
        };
    }
}
