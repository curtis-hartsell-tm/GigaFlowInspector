# GigaFlowInspector
A Python tool for detecting high-volume data transfers in network traffic. It aggregates netflow data to spotlight transfers exceeding set thresholds (e.g., 0.5 GB) and integrates IP reputation analysis via Microsoft Defender API, aiding in the identification of potential data exfiltration or significant network activities.

## Requirements
`pip install -r requirements.txt`

- pandas
- requests
- tqdm
- azure-identity

In the GigaFlowInspector script, replace the following with your own values:

- `client_id = 'YOUR_CLIENT_ID'`
- `client_secret = 'YOUR_CLIENT_SECRET'`
- `tenant_id = 'YOUR_TENANT_ID'`
- `file_path = 'your_csv_file.csv'`

You will also need to make sure your Client ID has `ThreatIntelligence.Read.All` permissions in order to perform the IP reputation lookups with MDTI.
