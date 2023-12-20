import pandas as pd
import requests
from azure.identity import ClientSecretCredential
from tqdm import tqdm
import json

# Azure AD credentials
client_id = 'YOUR_CLIENT_ID'
client_secret = 'YOUR_CLIENT_SECRET'
tenant_id = 'YOUR_TENANT_ID'

# Function to get access token
def get_access_token(client_id, client_secret, tenant_id):
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }
    response = requests.post(token_url, data=token_data)
    return response.json().get("access_token")

# Function to get IP reputation from the MDTI API
def get_ip_reputation(ip, access_token):
    url = f'https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts/{ip}/reputation'
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        try:
            data = response.json()
            classification = data.get('classification', 'Unknown')
            return classification
        except json.JSONDecodeError:
            return "Failed to parse JSON response"
    else:
        return f"Failed with status code {response.status_code}"

# Replace with the path to your CSV file
file_path = 'your_csv_file.csv'

# Read the CSV file
df = pd.read_csv(file_path)

# Convert data transfer volume to GB and aggregate
df['total_gb'] = df['num_octets'] / (1024 * 1024 * 1024)
aggregated_df = df.groupby(['src_ip_addr', 'dst_ip_addr', 'dst_port'])['total_gb'].sum().reset_index()

# Filter for data transfers more than 0.5 GB
large_transfers = aggregated_df[aggregated_df['total_gb'] > 0.5]

# Sort by total_gb in descending order
large_transfers = large_transfers.sort_values(by='total_gb', ascending=False)

# Get unique IP addresses for IP reputation lookup
unique_ips = pd.concat([large_transfers['src_ip_addr'], large_transfers['dst_ip_addr']]).unique()

# Get access token
access_token = get_access_token(client_id, client_secret, tenant_id)

# Perform IP reputation lookup with progress bar
reputation_results = {}
for ip in tqdm(unique_ips, desc="Fetching IP Reputations", unit="IP"):
    reputation = get_ip_reputation(ip, access_token)
    reputation_results[ip] = reputation

# Map the reputation results back to the DataFrame
large_transfers['src_ip_reputation'] = large_transfers['src_ip_addr'].map(reputation_results)
large_transfers['dst_ip_reputation'] = large_transfers['dst_ip_addr'].map(reputation_results)

# Display the results
print(large_transfers[['src_ip_addr', 'src_ip_reputation', 'dst_ip_addr', 'dst_ip_reputation', 'dst_port', 'total_gb']])