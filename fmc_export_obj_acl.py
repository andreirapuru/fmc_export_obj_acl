import requests
import base64
import csv
import getpass
import json
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def get_auth_token(fmc_host, username, password):
    """
    Authenticate to FMC and retrieve auth token and domain UUID.
    """
    url = f"https://{fmc_host}/api/fmc_platform/v1/auth/generatetoken"
    credentials = f"{username}:{password}"
    auth_header = {"Authorization": f"Basic {base64.b64encode(credentials.encode('utf-8')).decode('utf-8')}"}
    
    response = requests.post(url, headers=auth_header, verify=False)
    if response.status_code != 204:
        raise Exception(f"Authentication failed: {response.status_code} - {response.text}")
    
    access_token = response.headers.get('X-auth-access-token')
    domain_uuid = response.headers.get('DOMAIN_UUID')
    
    if not access_token or not domain_uuid:
        raise Exception("Failed to retrieve auth token or domain UUID.")
    
    return access_token, domain_uuid

def get_extended_access_lists(fmc_host, access_token, domain_uuid):
    """
    Retrieve all extended access lists with pagination handling.
    """
    base_url = f"https://{fmc_host}/api/fmc_config/v1/domain/{domain_uuid}/object/extendedaccesslists"
    headers = {
        "X-auth-access-token": access_token
    }
    
    all_acls = []
    offset = 0
    limit = 300  # Adjust as needed, max is typically 1000
    while True:
        params = {
            "offset": offset,
            "limit": limit,
            "expanded": True
        }
        response = requests.get(base_url, headers=headers, params=params, verify=False)
        if response.status_code != 200:
            raise Exception(f"Failed to retrieve access lists: {response.status_code} - {response.text}")
        
        data = response.json()
        items = data.get("items", [])
        all_acls.extend(items)
        
        # Check for next page
        if "next" not in data.get("links", {}):
            break
        offset += limit
    
    return all_acls

def resolve_name(fmc_host, access_token, domain_uuid, obj):
    """
    Resolve the name of an object by fetching it via API.
    """
    obj_type = obj.get("type", "")
    if not obj_type:
        return ""

    type_to_endpoint = {
        "Host": "hosts",
        "Network": "networks",
        "Range": "ranges",
        "FQDN": "fqdns",
        "NetworkGroup": "networkgroups",
        "ProtocolPortObject": "protocolportobjects",
        "PortGroup": "portobjectgroups",
        "ICMPV4Object": "icmpv4objects",
        "ICMPV6Object": "icmpv6objects",
        "SecurityGroupTag": "securitygrouptags",
        "UserGroup": "usergroups",
        # Add more as needed
    }

    endpoint = type_to_endpoint.get(obj_type)
    if not endpoint:
        # Fallback to any available name or value
        return obj.get("name", obj.get("value", obj.get("port", obj.get("protocol", obj.get("tag", "")))))

    url = f"https://{fmc_host}/api/fmc_config/v1/domain/{domain_uuid}/object/{endpoint}/{obj.get('id')}"
    headers = {"X-auth-access-token": access_token}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        return ""

    data = response.json()
    return data.get("name", "")

def extract_items(fmc_host, access_token, domain_uuid, container, item_type='network'):
    """
    Extract items from objects and literals, resolving names for objects.
    """
    items = []
    # Objects
    for obj in container.get("objects", []):
        name = obj.get("name", "")
        if not name:
            name = resolve_name(fmc_host, access_token, domain_uuid, obj)
        if name:
            items.append(str(name))
    # Literals
    if item_type == 'network':
        lit_key = 'value'
    elif item_type == 'port':
        lit_key = 'port'
    elif item_type == 'protocol':
        lit_key = 'protocol'
    elif item_type == 'sgt':
        lit_key = 'tag'
    else:
        lit_key = 'name'
    for lit in container.get("literals", []):
        val = lit.get(lit_key, "")
        if val:
            items.append(str(val))
    return items

def export_to_csv(fmc_host, access_token, domain_uuid, acls, csv_filename):
    """
    Export the extended access lists to a CSV file.
    Flattens the entries for each ACL into rows.
    """
    fieldnames = [
        "ACL_Name", "Sequence", "Action", "Source_Network", "Source_Port",
        "Destination_Network", "Destination_Port", "Application", "Users",
        "SGT", "Log_Level", "Log_Interval"
    ]
    
    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        
        for acl in acls:
            acl_name = acl.get("name", "")
            entries = acl.get("entries", [])
            sequence = 0
            
            for entry in entries:
                sequence += 1
                source_networks = extract_items(fmc_host, access_token, domain_uuid, entry.get("sourceNetworks", {}), 'network')
                dest_networks = extract_items(fmc_host, access_token, domain_uuid, entry.get("destinationNetworks", {}), 'network')
                source_ports = extract_items(fmc_host, access_token, domain_uuid, entry.get("sourcePorts", {}), 'port')
                dest_ports = extract_items(fmc_host, access_token, domain_uuid, entry.get("destinationPorts", {}), 'port')
                protocols = extract_items(fmc_host, access_token, domain_uuid, entry.get("protocols", {}), 'protocol')
                applications = extract_items(fmc_host, access_token, domain_uuid, entry.get("applications", {}), 'application')
                users = extract_items(fmc_host, access_token, domain_uuid, entry.get("users", {}), 'user')
                sgts = extract_items(fmc_host, access_token, domain_uuid, entry.get("sourceSecurityGroupTags", {}), 'sgt')
                
                row = {
                    "ACL_Name": acl_name,
                    "Sequence": sequence,
                    "Action": entry.get("action", ""),
                    "Source_Network": "; ".join(source_networks),
                    "Source_Port": "; ".join(source_ports),
                    "Destination_Network": "; ".join(dest_networks),
                    "Destination_Port": "; ".join(dest_ports),
                    "Application": "; ".join(applications),
                    "Users": "; ".join(users),
                    "SGT": "; ".join(sgts),
                    "Log_Level": entry.get("logLevel", ""),
                    "Log_Interval": entry.get("logInterval", "")
                }
                writer.writerow(row)

if __name__ == "__main__":
    fmc_host = input("Enter FMC host (IP or hostname): ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    csv_filename = input("Enter CSV filename (default: extended_access_lists.csv): ") or "extended_access_lists.csv"
    
    try:
        access_token, domain_uuid = get_auth_token(fmc_host, username, password)
        acls = get_extended_access_lists(fmc_host, access_token, domain_uuid)
        export_to_csv(fmc_host, access_token, domain_uuid, acls, csv_filename)
        print(f"Successfully exported {len(acls)} access lists to {csv_filename}")
    except Exception as e:
        print(f"Error: {str(e)}")
