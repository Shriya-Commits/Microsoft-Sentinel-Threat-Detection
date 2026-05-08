# KQL Queries

This folder contains Microsoft Sentinel KQL detections used in the SOC lab.

Queries include:
- `recon_detection.kql` — Detects whoami, ipconfig, net user, net localgroup
- `encoded_command_detection.kql` — Detects PowerShell `-EncodedCommand` flag
- `ep_bypass_detection.kql` — Detects PowerShell `-ep bypass` flag
- `failed_login_detection.kql` — Detects brute force patterns via Event ID 4625
