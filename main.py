import requests
import json
import csv
import getpass
import argparse
import warnings
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import SSLError

VERIFY_SSL = True
EXCLUDE_OBJECTS = [
    "IPv4-Private-10.0.0.0-8",
    "IPv4-Private-172.16.0.0-12",
    "IPv4-Private-192.168.0.0-16",
    "any-ipv4",
    "any-ipv6"
]

def get_fdm_token(host,port,username,password,verify_ssl):   
    url = f"https://{host}:{port}/api/fdm/latest/fdm/token"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    data = {
        "grant_type": "password",
        "username": username,
        "password": password
    }
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=verify_ssl)
        response.raise_for_status()  # Raise an HTTPError if the HTTP request returned an unsuccessful status code
        
        token_info = response.json()
        return token_info.get("access_token")
    
    except SSLError as ssl_error:
        print(f"SSL Error occurred: {ssl_error}")
        raise  # Re-raise the exception to be caught by the outer function
    
    except requests.RequestException as e:
        print(f"Error occurred: {e}")
        return None


def get_fdm_token_with_ssl_check(host, port, username, password):
    global VERIFY_SSL
    try:
        return get_fdm_token(host, port, username, password,verify_ssl=VERIFY_SSL)
    except SSLError:
        print("SSL certificate verification failed during token retrieval.")
        choice = input("\033[93mDo you want to proceed without verifying SSL? (yes/no):\033[0m ").strip().lower()
        if choice == 'yes':
            warnings.simplefilter('ignore', InsecureRequestWarning)  # Suppress the warning
            VERIFY_SSL = False
            return get_fdm_token(host, port, username, password, verify_ssl=VERIFY_SSL)
        else:
            print("Exiting due to SSL verification failure during token retrieval.")
            return None

def make_request(host, port, endpoint, token, verify_ssl=VERIFY_SSL, method="GET", data=None):   
    url = f"https://{host}:{port}{endpoint}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, verify=verify_ssl)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=json.dumps(data), verify=verify_ssl)
        elif method == "PUT":
            response = requests.put(url, headers=headers, data=json.dumps(data), verify=verify_ssl)
        response.raise_for_status()
        return response.json()
    
    except requests.RequestException as e:
        print(f"Error occurred: {e}")
        return {}

def get_network_objects(host, port, token, verify_ssl=VERIFY_SSL):
    endpoint = "/api/fdm/latest/object/networks"
    response_data = make_request(host, port, endpoint, token, verify_ssl)
    
    return response_data.get("items", [])

def get_firewall_serial(host, port,token, verify_ssl=VERIFY_SSL):
    endpoint = "/api/fdm/latest/operational/systeminfo/default"
    try:
        response_data = make_request(host, port, endpoint, token, verify_ssl)
        return response_data.get("serialNumber", "UNKNOWN_SERIAL")
    except requests.RequestException as e:
        print(f"Error occurred while fetching firewall serial: {e}")
        return "UNKNOWN_SERIAL"

def export_to_csv(network_objects, serial):
       # Define the CSV headers based on the fields you want to export
    headers = ["id", "name", "type", "subType", "value", "description","version"]
    timestamp = datetime.now().strftime('%Y%m%d_%H_%M_%S')  # e.g., '20230818123045' for Aug 18, 2023, 12:30:45
    if serial != 'UNKNOWN_SERIAL':
        filename = f"firewall_network_objects_{serial}_{timestamp}.csv"
    else:
        filename = f"firewall_network_objects_{timestamp}.csv"
    with open(filename, "w", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        
        for obj in network_objects:
            writer.writerow({
                "id": obj.get("id"),
                "name": obj.get("name"),
                "type": obj.get("type"),
                'subType': obj.get('subType', ''),
                "value": obj.get("value"),
                "description": obj.get("description", ""),
                'version': obj.get('version', '')
            })

def import_from_csv(filename,host, port,token,existing_objects,verify_ssl=VERIFY_SSL):
    endpoint = "/api/fdm/latest/object/networks"
    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Construct the network object data from the CSV row
            existing_object = next((obj for obj in existing_objects if obj['name'] == row['name']), None)
            data = {
                "name": row["name"],
                "type": row["type"],
                "value": row["value"],
                "subType": row["subType"],
                "description": row.get("description", "")
                }
            if existing_object:
                fields_to_compare = ['name', 'subType', 'value']

                differences = {k: (v, existing_object[k]) for k, v in row.items() if k in fields_to_compare and existing_object[k] != v}
                
                if differences:
                    differences_str = ', '.join([f"{k}: (old: {existing_object[k]}, new: {v[0]})" for k, v in differences.items()])
                    print(f"Object {row['name']} already exists with differences: {differences_str}")
                    choice = input("Do you want to override? (yes/no): ").strip().lower()
                    if choice == 'yes':
                        # Update the existing object
                        update_url = f"{endpoint}/{existing_object['id']}"
                        update_data = {
                            "version": existing_object['version'],  # Important: Use the version from the existing object
                            "name": row['name'],
                            "subType": row['subType'],
                            "value": row['value'],
                            "type": "networkobject"
                        }
                        
                        # Optional fields
                        if 'description' in row:
                            update_data['description'] = row['description']
                        if 'dnsResolution' in row:
                            update_data['dnsResolution'] = row['dnsResolution']
                        response_data = make_request(host, port, update_url, token, verify_ssl,method="PUT", data=update_data)
                        print(response_data)
                        if response_data:
                            print(f"Successfully updated {row['name']}.")
                        else:
                            print(f"Error updating {row['name']}")
                    else:
                        print(f"Skipping {row['name']}.")
                else:
                    print(f"Object {row['name']} already exists with no differences. Skipping.")
            else:
                try:
                    response_data = make_request(host, port, endpoint, token, verify_ssl,method="POST", data=data)
                    print(response_data)
                # Optionally, print a success message for each object
                    if response_data:
                        print(f"Successfully imported {row['name']}.")

                except requests.RequestException as e:
                    print(f"Error occurred while importing {row['name']}: {e}")
            
def login(host, port=443):
    global VERIFY_SSL
    username = input("Please enter the username: ")
    password = getpass.getpass("Please enter the password: ")
    token = get_fdm_token_with_ssl_check(host, port, username, password)
    if not token:
        print("Failed to authenticate. Exiting.")
        return
    return token
def main_export(host=None, port=443):
    token = login(host,port)
    try:
        network_objects = get_network_objects(host, port, token,VERIFY_SSL)
        filtered_network_objects = [obj for obj in network_objects if obj["name"] not in EXCLUDE_OBJECTS]
        serial = get_firewall_serial(host, port, token,VERIFY_SSL)
        export_to_csv(filtered_network_objects, serial)
    except SSLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            print("SSL certificate verification failed during data retrieval.")
        else:
            print("Exiting due to SSL verification failure during data retrieval.")

def main_import(filename, host=None, port=443):
    token = login(host,port)
    try:
        existing_objects = get_network_objects(host, port, token,VERIFY_SSL)
        import_from_csv(filename,host, port, token,existing_objects,verify_ssl=VERIFY_SSL)
    except SSLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            print("SSL certificate verification failed during data retrieval.")
        else:
            print("Exiting due to SSL verification failure during data retrieval.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A tool to fetch, export, and import network objects from and to FDM.",
        epilog="""Examples:
        1. Export network objects to a CSV:
           python main.py --host 192.168.1.1 --export
           
        2. Import network objects from a CSV:
           python main.py --host 192.168.1.1 --import firewall_network_objects_9A8MABCDFG_20230105_12_26_10.csv
           
        3. Use a different port and trust the SSL certificate:
           python main.py --host 192.168.1.1 --port 8443 --trust-cert --export
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", help="The IP address or hostname of the FDM.")
    parser.add_argument("--port", type=int, default=443, help="The port number for the FDM. Default is 443.")
    parser.add_argument("--trust-cert", action="store_true", help="Trust the SSL certificate.")
    
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--export", action="store_true", help="Export network objects from FDM to a CSV file.")
    action_group.add_argument("--import", dest="import_file", metavar="FILENAME", help="Import network objects to FDM from a CSV file.")
    
    args = parser.parse_args()
    if args.trust_cert:
        VERIFY_SSL = False
    if args.export:
        main_export(host=args.host, port=args.port)
    elif args.import_file:
        main_import(filename=args.import_file,host=args.host, port=args.port)