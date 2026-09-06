class Profile {
    constructor(schemaVersion = 1, trustPoints = {}, settings = null, frozenCookies = {}) {
        this.schemaVersion = schemaVersion;
        this.trustPoints = trustPoints;
        this.settings = settings || {
            misc: { allowNotification: true, renderColorBadge: true },
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
            }
        };
        this.frozenCookies = frozenCookies || {};
    }

    static fromJSON(json) {
        if (!json) return new Profile();
        return new Profile(json.schemaVersion ?? 1, json.trustPoints ?? {}, json.settings ?? new Profile().settings, json.frozenCookies ?? {});
    }

    toJSON() {
        return {
            schemaVersion: this.schemaVersion,
            trustPoints: this.trustPoints,
            settings: this.settings,
            frozenCookies: this.frozenCookies
        };
    }
}
