![GCPwnLogo](https://github.com/user-attachments/assets/1ad93c63-37f2-42fd-95e9-ec05966cb6b2)

[![PyPI](https://img.shields.io/pypi/v/gcpwn)](https://pypi.org/project/gcpwn/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](./LICENSE)
[![Stars](https://img.shields.io/github/stars/NetSPI/gcpwn.svg)](https://github.com/NetSPI/gcpwn/stargazers)
[![Forks](https://img.shields.io/github/forks/NetSPI/gcpwn.svg)](https://github.com/NetSPI/gcpwn/network)
[![Issues](https://img.shields.io/github/issues/NetSPI/gcpwn.svg)](https://github.com/NetSPI/gcpwn/issues)

# GCPwn

## Table of Contents

- [Overview](#overview)
- [Documentation](#documentation)
- [Installation TLDR](#installation-tldr)
- [First-Run TLDR](#first-run-tldr)
- [Unauthenticated Run TLDR](#unauthenticated-run-tldr)
- [OpenGraph TLDR](#opengraph-tldr)
- [Module/Data Output TLDR](#moduledata-output-tldr)
- [Scripts Folder TLDR](#scripts-folder-tldr)
- [Dependency Inventory](#dependency-inventory)
- [Repository Layout](#repository-layout)
- [Who Is This For?](#who-is-this-for)
- [Author, Contributors, and License](#author-contributors-and-license)
- [Resources](#resources)
- [Credits](#credits)

## Overview

> In the spirit of transparency: parts of this project and documentation were developed with LLM coding assistance. Review code and behavior in your environment before operational use. Ideally the dependency summary at the end of the README and explanations throughout should be enough to meet and verify your operational needs.

GCPwn (gee-see-pwn) is a Google Cloud offensive security assessment framework built for workspace-driven credential handling, service enumeration, artifact collection, and graph-based attack-path analysis.

It is designed as a one-stop shop for three primary workflows:

- **Reconnaissance and Enumeration:** Use success/fail API behavior trackedin the background, explicit `testIamPermissions` calls, and IAM binding analysis to understand effective permissions from clear-box (probably a config audit) to opaque scenarios (finding creds during a pentest). Export data in JSON/CSV/Excel formats, download artifacts as they are found (for example, Artifact Registry Python packages), and run broad discovery with `enum_all` and download data throughout with the `--download` flag.
- **Exploitation:** Execute pre-packaged exploit workflows for blue-team validation and professional penetration-testing exercises.
- **Graphing and OpenGraph:** Convert collected data into OpenGraph output for BloodHound-style analysis (see below). By default, graphing focuses on selected privilege-escalation edges and can be expanded with more verbose output, inheritance evaluation, and multi-permission edge logic.

<p><strong><span style="color:red">Disclaimer:</span></strong> <span style="color:red">Use this tool only in systems, projects, and environments you own or are explicitly authorized to assess. Unauthorized use may violate law, policy, or terms of service.</span></p>


## Documentation

Documentation is maintained in the GitHub Wiki:

- https://github.com/NetSPI/gcpwn/wiki

Quick wiki links:

- Getting Started: https://github.com/NetSPI/gcpwn/wiki/Getting-Started
- Authentication Reference: https://github.com/NetSPI/gcpwn/wiki/Authentication-Reference
- Workspace Instructions: https://github.com/NetSPI/gcpwn/wiki/Workspace-Instructions
- CLI Module Reference: https://github.com/NetSPI/gcpwn/wiki/CLI-Module-Reference
- Common Use Cases: https://github.com/NetSPI/gcpwn/wiki/Common-Use-Cases
- OpenGraph Overview and Usage: https://github.com/NetSPI/gcpwn/wiki/OpenGraph-Overview-and-Usage
- OpenGraph Add Your Own Content: https://github.com/NetSPI/gcpwn/wiki/OpenGraph-Add-Your-Own-Content

Additional project docs:

- Contributing: `CONTRIBUTING.md`
- Roadmap: `ROADMAP.md`
- License: `LICENSE`

## Installation TLDR

The installation strategy is to keep non-google dependencies minimal hopefully making it easier for you to get the tool approved if needed. `xlsxwriter` and `prettytable` are optional and can be installed only if you want those extra features, as shown below.

### Option 1: Local Git Clone Install

```bash
git clone https://github.com/NetSPI/gcpwn.git
cd gcpwn

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
```

Base install (no optional table/excel dependencies):

```bash
pip install -r requirements.txt
```

Install optional table output support:

```bash
pip install prettytable==3.17.0
```

Install optional Excel export support:

```bash
pip install xlsxwriter==3.2.9
```

Run the tool:

```bash
python -m gcpwn
```

### Option 2: Pip Install (PyPI)

```bash
pip3 install gcpwn
```

If you want optional table rendering (table std output option in configs) and/or Excel export support (`data export excel` option):

```bash
pip3 install "gcpwn[table]"
pip3 install "gcpwn[excel]"
# both extras
pip3 install "gcpwn[table,excel]"
```

Run the tool:

```bash
gcpwn
```

If your shell cannot find `gcpwn`, run:

```bash
python -m gcpwn
```

### Option 3: Release Download

Download a release binary from GitHub Releases:

- https://github.com/NetSPI/gcpwn/releases

Use the binary asset that aligns with your operating system and CPU architecture (for example, Linux/macOS/Windows and `amd64` vs `arm64`).

Example (Linux/macOS):

```bash
chmod +x ./gcpwn
./gcpwn
```

### Option 4: Docker

```bash
docker build -t gcpwn .
docker run --rm -it gcpwn
```

Build with optional extras (if you want table rendering and/or Excel export available in the container):

```bash
# prettytable extra
docker build --build-arg GCPWN_EXTRAS=table -t gcpwn .

# xlsxwriter extra
docker build --build-arg GCPWN_EXTRAS=excel -t gcpwn .

# both extras
docker build --build-arg GCPWN_EXTRAS=table,excel -t gcpwn .
```

If you want local persistence for DB/output between runs, mount volumes:

```bash
docker run --rm -it \
  -v "$(pwd)/databases:/opt/gcpwn/databases" \
  -v "$(pwd)/gcpwn_output:/opt/gcpwn/gcpwn_output" \
  gcpwn
```

## First-Run TLDR

1. Create/select a workspace by starting the program using one of the commands in the Installation section above.
2. Load credentials (user/service/OAuth token). If you are using `gcloud`, you may need to run `gcloud config set project <PROJECT_ID>` when loading ADC-style credentials.
3. Start with broad enumeration, ideally with **ONE of the options below**:

```bash
# Minimal first pass: enumerate discovered resources only (no testIamPermissions or download calls).
modules run enum_all

# Common first pass: run testIamPermissions checks on supported resources.
# Also runs a condensed list of permissions for org/folder/project resources.
modules run enum_all --iam

# Common first pass + downloads: run testIamPermissions and attempt content downloads where supported.
modules run enum_all --iam --download

# In-depth pass: --all-permissions includes large org/folder/project permission sets (10,000+ perms, executed in batches). Can take some time.
# See: gcpwn/modules/resourcemanager/utilities/data/all_*_permissions.txt for the full list or to customize it.
modules run enum_all --iam --all-permissions

# In-depth pass + downloads: enable artifact/content downloads where supported.
# Use `modules run enum_all -h` for token options.
# Example token: cloudrun_revision_env
modules run enum_all --iam --all-permissions --download
```

4. Review what was collected:

```bash
# Downloaded artifacts are written under gcpwn_output/ by default.

# Export collected data.
# CSV/JSON work in base install; Excel requires the optional Excel dependency from the installation section.
data export csv
data export json
data export excel

# Review current credential permissions discovered via testIamPermissions.
# Use --csv to export full row-level permission data (to avoid truncation in terminal output).
creds info
creds info --csv

# Process enumerated IAM bindings and build IAM summaries.
modules run process_iam_bindings

# Build BloodHound-compatible graph JSON.
# Import output.json into BloodHound CE:
# https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart
modules run enum_gcp_cloud_hound_data --expand-inheritance --reset --out output.json
```

## Unauthenticated Run TLDR

Sometimes you may want to run unauthenticated or quick modules without starting a full interactive session. You can run unauthenticated modules directly without entering the interactive workspace shell. This implicitly creates a workspace called `PASSTHROUGH`.

Examples:

```bash
# Run via installed console script
gcpwn --module unauth_apikey_enum_all_scopes --api-key AIza...

# Same flow via python module entrypoint
python -m gcpwn --module unauth_apikey_gemini_exploit --api-key AIza...
```

## OpenGraph TLDR

By default, the OpenGraph module only graphs edges and related resource edges tied to privilege escalation paths. The default OpenGraph escalation-rule allowlist lives in `gcpwn/mappings/og_privilege_escalation_paths.json`. Review the wiki for explanations of the available flags, but the best option is usually the following:
```bash
modules run enum_gcp_cloud_hound_data --expand-inheritance --reset --out Bloodhound_Output.json
```

### Graphing Strategy

You might notice edges go to `role@location` instead of going directly to the project. This preserves authorization fidelity in the graph. If User A has `compute.admin` on Project A and User B has `storage.admin` on Project A, drawing both users directly to Project A and then Project A to all resources would incorrectly imply both users can reach the same resources when User A can only get to compute and User B can only get to storage. The correct model is to route each user through their specific role binding node at that location, and only then fan out to resources that role can actually affect.

Incorrect method (over-broad reach):

```text
User A --> Project A --> Compute & Storage
User B --> Project A --> Compute & Storage
```

Correct method (binding-scoped reach):

```text
User A --> compute_admin@project:A --> Compute Resources in Project A
User B --> storage_admin@project:A --> Storage Resources in Project A
```

![OpenGraph example graph](images/Opengraph_Example.png)

Generate OpenGraph JSON:

```bash
modules run enum_gcp_cloud_hound_data --out opengraph_output.json --reset [--include-all] [--expand-inherited] [--cond-eval]

# Example
(<staging-project-2>:ABC)> modules run enum_gcp_cloud_hound_data --expand-inherited --reset --out my_output.json
[*] Step 1: users_groups (Users/Groups graph)
[*] Completed users_groups: +92 nodes, +0 edges
[*] Step 2: iam_bindings (IAM bindings graph)
[*] Completed iam_bindings: +109 nodes, +201 edges
[*] Step 3: inferred_permissions (Inferred permissions graph)
[*] Completed inferred_permissions: +2 nodes, +2 edges
[*] Step 4: resource_expansion (Resource expansion graph)
[*] Completed resource_expansion: +63 nodes, +62 edges
[*] Pruned isolated service-account IAM-binding islands (pairs=17, key_islands=5, nodes=50, edges=28).
[*] Pruned orphan implied-IAM-binding nodes (implied_bindings=2, nodes=2, edges=2).
[*] Pruned isolated service-account nodes (service_accounts=43, nodes=43, edges=0).
[*] OpenGraph generation complete. Nodes: 171 | Edges: 235
[*] Saved graph JSON to my_output.json


# Pass the output JSON into your local installation of BloodHound
> head TEST.json -n 20
{
  "metadata": {
    "source_kind": "GCPBase"
  },
  "graph": {
    "nodes": [
      {
        "id": "allUsers",
        "kinds": [
          "GCPAllUsers",
          "GCPPrincipal"
        ],
        "properties": {
          "display_name": "allUsers",
          "source": "iam_members"
        }
      },
      {
        "id": "combo_iambinding:RESET_COMPUTE_STARTUP_SA@project:<Project_ID>#06e0003fe1",
        "kinds": [
      [TRUNCATED]

```

Optional flags:

- `--include-all`: include broader relationship output that might not be a direct privilege-escalation path (for example, a binding that exists but is not a direct avenue to escalate privileges).
- `--expand-inherited`: expand inherited IAM scope relationships.
- `--cond-eval`: currently preserves conditional workflow plumbing (placeholder behavior).
- `--reset`: clear prior OpenGraph DB state before generation.

Then import the JSON into [BloodHound CE](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart).

### Adding Your Own Edges TLDR

If you want to add your own privilege-escalation edge (or any edge) to be called out by default, edit `og_privilege_escalation_paths.json` and add your rule. You need to know which permissions you want to flag. We cover adding a single-permission edge below, and the wiki covers multi-permission edge rules.

#### Add a Single-Permission Edge

Let's assume we want to call out `cloudkms.cryptoKeys.update` and add it to our default single-permission rules.

1. Add to the permission --> role dictionary
   - If your target permission (i.e. `cloudkms.cryptoKeys.update`) is not already included, add the permission on a newline to `scripts/build_predfined_perm_to_role_input.txt`
   - With your own GCP creds (for example, a free GCP account) in your own private GCP environment, run `./build_predefined_perm_to_roles.sh build_predfined_perm_to_role_input.txt > perm_to_role_mappings.json` as an authenticated user. This bash script gets all permissions for all predefined roles in a GCP environment to show which roles map to your target permission. You can also add the mapping manually to `gcpwn/data/core/mappings/og_permission_to_roles_map.json` using https://docs.cloud.google.com/iam/docs/roles-permissions
   - You should see the permission --> role(s) mapping in `perm_to_role_mappings.json`. Replace `gcpwn/data/core/mappings/og_permission_to_roles_map.json` with content of `perm_to_role_mappings.json`
2. Add a rule definition to `og_privilege_escalation_paths.json` (Note multi-permission rules are covered in the wiki). In our case, it might look like the entry below. Note `resource_scopes_possible` is where one might see a binding with those permissions, and `resource_types` are the actual resource nodes you will be drawing edges to. For example, you might see `cloudkms.cryptoKeys.update` attached to a project IAM binding or attached directly to a key IAM binding, but the final node in either case will be a key node and NOT a project per the reasoning stated above. If `cloudkms.cryptoKeys.update` is attached to a project IAm binding, gcpwn will fan out edges to key nodes discovered in that project rather than end at a project node.

```json
"single_permission_rules": {
  "CAN_DISABLE_KMS_KEY": {
    "permission": "cloudkms.cryptoKeys.update",
    "description": "Can update KMS crypto key settings including disabling or changing key behavior.",
    "resource_scopes_possible": ["project", "kmscryptokey"],
    "target_selector": {
      "mode": "resource_types",
      "resource_types": ["kmscryptokey"]
    }
  }
}
```

3. A final OpenGraph edge might then look like the following when ingested in BloodHound

```text
user:alice@example.com
  -[HAS_IAM_BINDING]->
iambinding:roles/cloudkms.admin@project:my-project
  -[CAN_DISABLE_KMS_KEY]->
resource:projects/my-project/locations/us-central1/keyRings/prod/cryptoKeys/app-key
```

### OpenGraph Cypher TLDR

These examples assume your OpenGraph JSON has already been imported into Neo4j/BloodHound-compatible tooling. Remove/alter `LIMIT` line as needed.

1. See all nodes and edges

```cypher
MATCH (n)-[r]->(m)
RETURN n, r, m
LIMIT 1000
```

2. See all nodes and edges minus service-agent-associated data

```cypher
MATCH (n)-[r]->(m)
WHERE coalesce(n.is_service_agent, false) = false
  AND coalesce(m.is_service_agent, false) = false
  AND coalesce(n.service_agent_role, false) = false
  AND coalesce(m.service_agent_role, false) = false
RETURN n, r, m
LIMIT 1000
```

3. See all nodes and edges where IAM edges are inferred only

```cypher
MATCH (p)-[:HAS_IMPLIED_PERMISSIONS]->(g)-[r]->(t)
WHERE type(r) STARTS WITH "INFERRED_"
RETURN p, g, r, t
LIMIT 1000
```

4. See all nodes and edges where IAM edges are binding-based only

```cypher
MATCH (p)-[seed:HAS_IAM_BINDING|HAS_COMBO_BINDING]->(g)
OPTIONAL MATCH (g)-[r]->(t)
WHERE r IS NULL OR NOT type(r) STARTS WITH "INFERRED_"
RETURN p, seed, g, r, t
LIMIT 1000
```

5. Find paths to `roles/owner` or any custom role (replace `ABC_Name`)

```cypher
MATCH p=(principal)-[:HAS_IAM_BINDING]->(binding:GCPIamSimpleBinding)
WHERE binding.role_name IN ["roles/owner", "ABC_Name"]
OPTIONAL MATCH (binding)-[r]->(target)
RETURN principal, binding, r, target, p
LIMIT 1000
```

6. Identify paths where a service account leads to another service account

```cypher
MATCH p=(sa1:GCPServiceAccount)-[*1..6]->(sa2)
WHERE (sa2:GCPServiceAccount OR sa2:GCPServiceAccountResource)
  AND sa1 <> sa2
RETURN p
LIMIT 500
```

## Module/Data Output TLDR

### Module output format

Default output is `text`. You can switch workspace output format with:

```text
configs list
configs set std_output_format text
configs set std_output_format table
```

`table` mode requires the optional dependency `prettytable` covered in the installation section above.

### Data output and exports

```text
# Export all collected service data to one CSV blob
data export csv

# Export all collected service data to one JSON blob
data export json

# Export all collected service data to one Excel workbook
data export excel

# Export all collected service data to a specific Excel file path
data export excel --out-file ./gcpwn_export.xlsx

# Export hierarchy image (SVG)
data export treeimage

# Run direct SQL against SQLite (service DB by default)
data sql --db service "SELECT * FROM iam_allow_policies LIMIT 25"

# Wipe service DB rows for current workspace (destructive)
data wipe-service --yes
```

## Scripts Folder TLDR

Scripts under `scripts/` are included in this GitHub repository to support setup, customization, and development workflows.

They are not required for normal tool usage and are not part of the standard runtime path for the installed package.

Use them when you want to modify behavior, regenerate mapping data, or follow advanced project workflows.

For context, review the wiki and the OpenGraph instructions for adding an edge in this README.

## Dependency Inventory

Direct runtime dependencies are sourced from `requirements.txt` (and loaded via `pyproject.toml`).

### Core utilities

- `boto3>=1.43.6,<2` (includes `botocore` transitively)
- `pandas==3.0.2`
- `requests==2.33.1`

### Google API and auth libraries

- `google-api-core==2.30.3`
- `google-api-python-client==2.196.0`
- `google-auth-httplib2==0.4.0`
- `google-auth-oauthlib==1.4.0`

### Google Cloud client libraries

- `google-cloud-*` packages are pinned in `requirements.txt` (for example: `google-cloud-compute`, `google-cloud-storage`, `google-cloud-resource-manager`, `google-cloud-container`, etc.).

### Vertex/GenAI support

- `google-genai==1.74.0`

### Optional extras

- `prettytable==3.17.0` via `pip install "gcpwn[table]"`
- `xlsxwriter==3.2.9` via `pip install "gcpwn[excel]"`

### Dev-only extra

- `pytest>=9.0` via `pip install "gcpwn[dev]"`

### Release-build only dependency

- `pyinstaller==6.20.0` is used by `.github/workflows/build_release.yml` to package standalone executables for release artifacts.
- It is not required for normal runtime usage of GCPwn.

Tip: If you want an SBOM from GitHub, open this repository and go to `Insights` -> `Dependency graph`, then use `Export SBOM`.

## Repository Layout

- `gcpwn/`: main package root.
- `gcpwn/__main__.py`: `python -m gcpwn` entrypoint.
- `gcpwn/cli/`: command processor and workspace command handlers.
- `gcpwn/core/`: session/config/db/runtime/export primitives.
- `gcpwn/modules/`: service modules (`everything`, `opengraph`, service-specific modules).
- `gcpwn/mappings/`: static mapping/config data used across modules.
- `tests/`: unit/integration/module tests.
- `databases/`: SQLite stores for workspaces, sessions, and service data.

## Who Is This For?

- **Pentesters:** automate large portions of GCP recon and exploit-path discovery.
- **Cloud security learners:** quickly map APIs/resources and permission behavior.
- **Security researchers:** batch module execution + centralized data/action collection for deeper analysis/proxying.

## Author, Contributors, and License

- Author: NetSPI
- License: BSD-3-Clause (`LICENSE`)
- Contributors: PRs and issues welcome

## Resources

Tool has changed in several ways and new videos are coming. For now, the following should provide a good resource:

- fwd:cloudsec 2024: https://www.youtube.com/watch?v=opvv9h3Qe0s
- DEF CON 32 Cloud Village: https://www.youtube.com/watch?v=rxXyYo1n9cw
- Introduction blog: https://www.netspi.com/blog/technical-blog/cloud-pentesting/introduction-to-gcpwn-part-1/

## Credits

Built on the shoulders of giants; inspiration, code, and/or supporting research included from:

- GMap API Scanner: https://github.com/ozguralp/gmapsapiscanner
- Rhino Security: https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- GCPBucketBrute: https://github.com/RhinoSecurityLabs/GCPBucketBrute
- Google Cloud Python docs: https://cloud.google.com/python/docs/reference
