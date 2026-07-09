#!/usr/bin/env bash
# Add the GDID / device-graph domains to Pi-hole v6. Run ON the Pi-hole box.
# Wildcards cover the parent domain AND every subdomain (handles regional rotation), so
# four rules replace the seven exact hostnames. Idempotent.
set -e

# parent domains -> wildcard covers them + all children
#   dds.microsoft.com          -> dds / fd.dds / aad.cs.dds / cs.dds .microsoft.com
#   do.dsp.mp.microsoft.com    -> geo.prod.do.dsp.mp... (Delivery Optimization DSP)
#   cdpcs.access.microsoft.com -> CDP connectivity
#   activity.windows.com       -> activity uploads carrying the device id
for d in dds.microsoft.com do.dsp.mp.microsoft.com cdpcs.access.microsoft.com activity.windows.com; do
  pihole --wild "$d"
done

# OPTIONAL / AGGRESSIVE: the MSA mint endpoint. Breaks Microsoft Store sign-in and MSA login.
# If you don't use a Microsoft Account, the Store is the only casualty. Uncomment to use:
# pihole --wild login.live.com

pihole reloaddns
echo "Done. Verify from a Windows client:  nslookup activity.windows.com <PIHOLE_IP>  -> expect 0.0.0.0"
echo "Or on the Pi-hole:  pihole -q aad.cs.dds.microsoft.com"
