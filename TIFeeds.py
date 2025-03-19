import csv
import pip._vendor.requests as requests
import os
from datetime import datetime
# Base URL to the source repository (replace with the actual base URL)
base_url = "https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/refs/heads/master/"

# Intel file to process
intel_file = "filetransferportals.intel"

# Fixed header sequence
fixed_header = ["domain", "category", "score", "first_seen", "last_seen", "ports", "ip", "url", "type", "file_hash"]

# Placeholder date for first_seen and last_seen (in yyyy-mm-dd format)
placeholder_date = datetime.now().strftime("%Y-%m-%d")  # Today's date in yyyy-mm-dd format

# Fetch the .intel file
intel_file_url = base_url + intel_file
response = requests.get(intel_file_url)
lines = response.text.splitlines()

# Remove the header (first line)
lines = lines[1:]

# Convert to CSV and save
csv_file_name = f"{os.path.splitext(intel_file)[0]}.csv"
with open(csv_file_name, mode='w', newline='', encoding='utf-8') as csv_file:
    csv_writer = csv.DictWriter(csv_file, fieldnames=fixed_header)
    csv_writer.writeheader()  # Write the fixed header

    for line in lines:
        # Split the line by tabs (assuming the .intel file is tab-separated)
        row_data = line.split('\t')
        
        # Initialize row with default values
        row = {
            "domain": "",
            "category": row_data[4] if len(row_data) > 4 else "",  # Use meta.desc as category
            "score": 0.0,
            "first_seen": placeholder_date,
            "last_seen": placeholder_date,
            "ports": "",
            "ip": "",
            "url": "",
            "type": row_data[1] if len(row_data) > 1 else "",  # Use indicator_type as type
            "file_hash": "",
        }
        
        # Set domain since we know these are domain indicators
        if len(row_data) > 0:
            row["domain"] = row_data[0]  # Set domain for domain-type indicators
            
        csv_writer.writerow(row)

print(f"Converted {intel_file} to {csv_file_name}")
