DarkWatch Workstation Validation Script
=======================================

The script `run_collector_validation.sh` is intended to be executed from the
Whonix Workstation USER session.

Usage inside Whonix Workstation:
--------------------------------
1. Ensure the shared folder `whonix_collector_share` is mounted or copied to `~/darkwatch_collector`.
2. Run:
   bash ~/darkwatch_collector/commands/run_collector_validation.sh
   or
   bash /media/sf_whonix_collector_share/commands/run_collector_validation.sh

Notes:
------
- This script only runs a connectivity safety check against https://check.torproject.org/api/ip.
- It does NOT access any Dark Web or .onion site.
- It does NOT modify network settings or SSH configuration.
- It does NOT modify any DarkWatch core project source code.
