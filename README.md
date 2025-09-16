# Cisco FMC Extended Access Lists Exporter

This Python script exports all extended access lists (ACLs) from a Cisco Firepower Management Center (FMC) to a CSV file using the FMC REST API. It retrieves ACL details, including entries (ACEs), and flattens them into a structured CSV format for easy analysis or migration.

## Features

- Authenticates to FMC using username and password.
- Handles pagination to fetch all extended ACLs.
- Extracts and resolves object names for networks, ports, protocols, applications, users, and Security Group Tags (SGTs).
- Supports literals (e.g., direct IP addresses or ports) and objects/object groups (displays names, not expanded contents).
- Exports to CSV with the following columns:
  - **ACL_Name**: Name of the ACL.
  - **Sequence**: Sequence number of the ACE (auto-incremented starting from 1).
  - **Action**: Permit or deny action.
  - **Source_Network**: Source networks/objects (semicolon-separated if multiple).
  - **Source_Port**: Source ports/objects (semicolon-separated if multiple).
  - **Destination_Network**: Destination networks/objects (semicolon-separated if multiple).
  - **Destination_Port**: Destination ports/objects (semicolon-separated if multiple).
  - **Application**: Applications/protocols (semicolon-separated if multiple).
  - **Users**: Users or user groups (semicolon-separated if multiple).
  - **SGT**: Source Security Group Tags (semicolon-separated if multiple).
  - **Log_Level**: Logging level for the ACE.
  - **Log_Interval**: Logging interval for the ACE.

## Requirements

- Python 3.6+
- Required libraries (install via `pip`):
  - `requests`
- Cisco FMC version 7.4.1 or compatible (based on the API documentation: [Cisco FMC REST API Quick Start Guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_741/Objects_In_The_REST_API.html#reference_2021921-729-76368512)).
- Read-only API access to FMC (username with sufficient permissions).

## Installation

1. Clone the repository:

   git clone https://github.com/yourusername/fmc-acl-exporter.git
   cd fmc-acl-exporter

3. Install dependencies:

   pip install requests

## Usage

Run the script from the command line. It will prompt for inputs interactively.

python fmc_acl_exporter.py


### Prompts:
- **Enter FMC host (IP or hostname)**: e.g., `fmc.example.com` or `192.168.1.100`.
- **Enter username**: Your FMC API username.
- **Enter password**: Your FMC API password (input is hidden).
- **Enter CSV filename (default: extended_access_lists.csv)**: Press Enter for default or provide a custom filename.

### Example Output:
Enter FMC host (IP or hostname): fmc.example.com

Enter username: apiuser

Enter password:

Enter CSV filename (default: extended_access_lists.csv):

Successfully exported 5 access lists to extended_access_lists.csv



The CSV file will be generated in the current directory.

### Error Handling:
- If authentication fails or API calls encounter issues, an error message will be printed (e.g., `Error: Authentication failed: 401 - Unauthorized`).

## Script Details

The script performs the following steps:
1. **Authentication**: Generates an access token and domain UUID via the FMC API.
2. **Fetch ACLs**: Retrieves all extended ACLs with pagination and expanded details.
3. **Resolve Names**: For objects without a `name` field, fetches the object details via API to get the name.
4. **Export to CSV**: Flattens ACL entries into rows, handling both objects (names) and literals.

### Key Functions:
- `get_auth_token()`: Handles authentication.
- `get_extended_access_lists()`: Fetches ACLs with pagination.
- `resolve_name()`: Resolves object names via API if not present.
- `extract_items()`: Extracts and formats items (objects/literals) for each field.
- `export_to_csv()`: Writes the data to CSV.

## Limitations
- Does not expand object group contents; only shows group names.
- Assumes the `expanded=True` parameter returns necessary details.
- Ignores SSL warnings (uses `verify=False`); for production, consider proper certificate validation.
- Sequence is auto-generated (not fetched from API if available).
- Tested with FMC 7.4.1 API; may need adjustments for other versions.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request. For major changes, open an issue first to discuss.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

For more details on the FMC API, refer to the [official Cisco documentation](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_741/Objects_In_The_REST_API.html).
