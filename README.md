# ClearSignal Diagnostics for GLPI 11

A ticket-level diagnostics plugin for GLPI 11 that lets engineers run network, DNS, website, and mail-authentication checks from the ticket screen and add a formatted summary back into the ticket as a private follow-up.

## Included checks
- Ping
- Traceroute
- Forward lookup (A/AAAA)
- Reverse lookup (PTR)
- DNS diagnostic
  - delegation trace
  - DNSSEC comparison with and without checking disabled
  - parent vs child NS consistency
  - Cloudflare proxy heuristic
  - resolver comparison across 1.1.1.1, 8.8.8.8 and 9.9.9.9
- Website check
- MX check
- SPF check
- DKIM check
- DMARC check

## Requirements
- GLPI 11
- PHP 8.1+
- Python 3.10+
- Python modules in `python/requirements.txt`
- System utilities available on the GLPI host:
  - `ping`
  - `traceroute` or `tracepath`

## Install
1. Copy the `clearsignaldiag` folder into `glpi/plugins/`
2. Install Python packages:
   `python3 -m pip install -r glpi/plugins/clearsignaldiag/python/requirements.txt`
3. In GLPI, go to **Setup > Plugins** and install/enable the plugin.
4. Open the plugin configuration page and confirm the Python path and timeout.
5. Open a ticket and use the **Diagnostics** tab.

## Notes
- The plugin uses a Python worker for the technical checks and returns JSON to GLPI.
- Results can be inserted into the current ticket as a private follow-up.
- This build is intended as a production-ready starter, but you should still test paths, permissions and host utility availability in your GLPI environment.
