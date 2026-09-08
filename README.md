# CookieJar

This is browser extension (developed for Firefox) offers a little set tools to manage online privacy and security. It allows users to view, edit, and delete specific cookies or stored information, as well as a trust score with which CookieJar tries to estimate the site's security and it's fully configurable (each of the external services requires an API key, that must be provided by the user).

It's still a prototype built for HAckClub.

---

## Features

### Cookie Inspector
Take a closer look at the cookies stored for the current domain and manage them directly from the extension.

You can:
* view cookies by domain
* edit cookie values
* delete cookies
* freeze/unfreeze cookies to preserve a snapshot of their state (a frozen cookie is invisible to the site and won't be sent with requests, but is stored in the extension, ready to be moved if needed)

This makes it easy to test websites, inspect tracking behaviors, or temporarily neutralize intrusive cookies without losing the original data.

### Trust Score
CookieJar evaluates a domain and assigns it a trust score from 0 to 100.

The score is based on multiple external checks, including:
* Google Safe Browsing
* AlienVault OTX
* PhishTank
* URLScan
* OpenPhish
* Tranco rank
* Domain age
* VirusTotal

If a site performs poorly across these signals, the score drops and the extension displays a warning.

### Connection details
From the connection details window a list of information are displayed, such as IP information (location, isp, reverse dns, ...), Domain info (registrar, expiration, creation, ...), etc.

If all dns and ip information are displayed as "Unknown" try pressing the reload button at the bottom. Sometimes dns information can stay as "unknown" or "N/A" , that's because they're not available on rdap.org API.

### Download Protection
When enabled, CookieJar can monitor downloads and check them with VirusTotal before they finish.

If a file is flagged as malicious enough to meet your configured threshold, the download is blocked automatically and a notification (if enabled) is sent.

### Storage Explorer
Inspect more than just cookies. CookieJar can also help you browse:
* localStorage
* sessionStorage
* extension storage

This is especially useful for debugging web apps or identifying suspicious data being written to browser storage.

### Dashboard
A dedicated dashboard gives you a clearer overview of the data CookieJar has collected over time.

You can review:
* total trust evaluations
* dangerous vs safe domains
* worst-rated sites
* historical trust score entries

The dashboard also shows which trust modules are enabled and how they are configured.

### Settings & Configuration
CookieJar is designed to be configurable.

You can adjust:
* which trust sources are enabled
* API keys for external services
* VirusTotal evaluation options
* notification preferences
* visual badge rendering for the extension
* if pages with 0 score points are loaded

### Whitelist & Blacklist
From the dashboard you can also put domains into one of these two categories:

- **whitelist** whitelisted domains are forced to a 100 trust score
- **blacklist** the domains are forced to a 0 trust score and are prevented from loading 

---

## Installation

### Firefox
#### Tested on Firefox 155.0.1 (64-bit)

If no signed `.xpi` is provided in the latest release: 

1. Clone or download this repository.
2. Open Firefox and navigate to `about:debugging`.
3. Click on **This Firefox** on the left menu.
4. Click **Load Temporary Add-on...** and select `manifest.json` inside the extension folder.

### Note
This extension relies on browser permissions and external APIs for trust evaluation and malware checks. Some features may require you to provide your own API keys in the settings page.

This extension is still a work in progress and may have bugs or optimization issues.

## Work in Progress
CookieJar is currently under occasional development!