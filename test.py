import os
import shutil
import subprocess
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configuration
#src_files = r'\\192.168.12.208\d$\EPSV\EPS.exe'
src_files = r'\\192.168.12.208\d$\EPSV\EPSDiscount.exe'

#src_files = r'\\192.168.12.208\d$\EPSV\EPS 05-12-2025.rar'  # Source file path in 12.208 Server
#src_files = r'\\192.168.12.208\d$\EPSV\POS Boss 21-01-26.zip'
# Configd
# src_files = [
#     os.path.normpath(r'\\172.16.52.41\d$\EPSV\EPS.exe'),
#     os.path.normpath(r'\\172.16.52.41\d$\EPSV\Deployment.txt')
# ]
src_files = os.path.normpath(src_files) #used for single file
#input_file = "All Active Servers-806- POS BOSS Old.xlsx"  # Input file containing server details
#input_file = "All Active Servers-650- POS BOSS Old.xlsx"  # Input file containing server details
#All Active Servers-650- POS BOSS Old.xlsx
#input_file = "Pos Boss-1.xlsx"  
#input_file = "POS Dep Failed-1.xlsx" 
#input_file = "test.xlsx" 

username = os.getenv("NET_USE_USERNAME")  # Username for remote authentication
password = os.getenv("NET_USE_PASSWORD")  # Password for remote authentication
if not username or not password:
    print("ERROR: NET_USE_USERNAME or NET_USE_PASSWORD not found in environment variables.")
    exit(1)
current_time = datetime.now().strftime("%d-%m-%Y %I.%M.%S %p")
output_file = f"File_Transfer_Status-{current_time}.xlsx"

# Verify source file exists
if not os.path.exists(src_files):
    
    print(f"Source file does not exist: {src_files}")
    exit(1)

# Read Server Details
df = pd.read_excel(input_file)
total_servers = len(df)
processed_count = 0

# Function to check if a server is online
def is_server_online(ip_address):
    try:
        result = subprocess.run(f"ping -n 1 {ip_address}", shell=True, capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error pinging {ip_address}: {e}")
        return False

# Function to copy file to server
def copy_file_to_server(outlet_code, ip_address):
    #dest_file = os.path.normpath(f'\\\\{ip_address}\\D$\\EPS_NEW\\EPS.exe')
    dest_file = os.path.normpath(f'\\\\{ip_address}\\D$\\EPS_NEW\\')
    #dest_file = os.path.normpath(f'\\\\{ip_address}\\D$\\EPS\\EPS\\')
    try:
        # Authenticate and map network drive
        subprocess.run(
            f"net use \\\\{ip_address} /user:{username} {password}",
            shell=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        shutil.copy(src_files, dest_file)
        return {"OutletCode": outlet_code, "IP": ip_address, "Status": "Successfully Replaced", "Details": ""}
    except Exception as e:
        return {"OutletCode": outlet_code, "IP": ip_address, "Status": "Failed to Replace", "Details": str(e)}
    finally:
        # Unmap the drive
        subprocess.run(
            f"net use \\\\{ip_address} /delete",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

# Function to Process a Single Server
def process_server(row):
    global processed_count
    processed_count += 1
    outlet_code = row['OutletCode']
    ip_address = row['IP']
    print(f"Deploying on {outlet_code}-{ip_address} ({processed_count}/{total_servers})...")

    if not is_server_online(ip_address):
        return {"OutletCode": outlet_code, "IP": ip_address, "Status": "Offline", "Details": ""}

    return copy_file_to_server(outlet_code, ip_address)

# Process all servers in parallel
results = []
with ThreadPoolExecutor() as executor:
    futures = [executor.submit(process_server, row) for _, row in df.iterrows()]
    for future in futures:
        results.append(future.result())

# Save results to Excel
if results:
    final_df = pd.DataFrame(results)
    final_df.to_excel(output_file, index=False)
    print(f"File Transfer Completed. Check {output_file} for details.")
else:
    print("No Data Retrieved from any of the Specified Servers.")
