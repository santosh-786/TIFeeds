

# URL to the raw .intel file in the source repository
#intel_file_url = "https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/refs/heads/master/compromised-ips.intel"
import csv
import pip._vendor.requests as requests
import os
from datetime import datetime
# Base URL to the source repository (replace with the actual base URL)
base_url = "https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/refs/heads/master/"

# List of .intel files to process
intel_files = [
    "abuse-ch-threatfox-ip.intel",
    "compromised-ips.intel",
    "tweetfeed.intel"
]

# Fixed header sequence
fixed_header = ["domain", "category", "score", "first_seen", "last_seen", "ports", "ip", "url", "type", "file_hash"]

# List to store all rows from all CSV files
all_rows = []

# Get current timestamp for filenames
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # Format: YYYYMMDD_HHMMSS

# Placeholder date for first_seen and last_seen (in yyyy-mm-dd format)
placeholder_date = datetime.now().strftime("%Y-%m-%d")  # Today's date in yyyy-mm-dd format

# Process each .intel file
for intel_file in intel_files:
    # Fetch the .intel file
    intel_file_url = base_url + intel_file
    response = requests.get(intel_file_url)
    lines = response.text.splitlines()

    # Remove the header (first line)
    lines = lines[1:]

    # Convert to CSV and save with timestamp
    csv_file_name = f"{os.path.splitext(intel_file)[0]}_{timestamp}.csv"  # Add timestamp to filename
    with open(csv_file_name, mode='w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=fixed_header)
        csv_writer.writeheader()  # Write the fixed header

        for line in lines:
            # Split the line by tabs (assuming the .intel file is tab-separated)
            row_data = line.split('\t')

            # Map the available data to the fixed header
            row = {
                "domain": "",  # Leave empty if not available
                "category": row_data[4] if len(row_data) > 4 else "",  # Use meta.desc as category
                "score": 0.0,  # Default score as 0.0 (float) if not available
                "first_seen": placeholder_date,  # Use placeholder date
                "last_seen": placeholder_date,  # Use placeholder date
                "ports": "",  # Leave empty if not available
                "ip": row_data[0] if len(row_data) > 0 else "",  # Use indicator as IP
                "url": "",  # Leave empty if not available
                "type": row_data[1] if len(row_data) > 1 else "",  # Use indicator_type as type
                "file_hash": "",  # Leave empty if not available
            }
            csv_writer.writerow(row)
            all_rows.append(row)  # Add the row to the all_rows list

    print(f"Converted {intel_file} to {csv_file_name}")

# Save all rows to a single all.csv file with timestamp
all_csv_file_name = f"all_{timestamp}.csv"
with open(all_csv_file_name, mode='w', newline='', encoding='utf-8') as all_csv_file:
    csv_writer = csv.DictWriter(all_csv_file, fieldnames=fixed_header)
    csv_writer.writeheader()  # Write the fixed header
    csv_writer.writerows(all_rows)  # Write all rows

print(f"Merged all CSV files into {all_csv_file_name}")
