# Google Workspace modules

Enumeration of **Google Workspace / Cloud Identity** — a distinct domain from
GCP. Workspace uses different credentials and scopes, is **tenant-scoped** (run
**once** per tenant, *not* once-per-project), and has its own data model. These
modules are complete and enumerate read-only, degrading gracefully (403/404)
when the credential lacks Workspace access.

## Layout

- `common.py` — shared infrastructure: `build_cloud_identity_service` /
  `build_directory_service`, domain-wide-delegation (`apply_workspace_delegation`
  → `creds.with_subject`), and `resolve_org_id` / `resolve_directory_customer_id`.
- `cloud_identity/` — the Cloud Identity API (users, groups, memberships).
- `directory/` — the Admin SDK Directory API (admin roles, org units, domains,
  mobile devices, OAuth token grants).
- `groups_settings/`, `data_transfer/` — other Admin SDK sub-APIs.
- `apps/drive/` — the Drive **data plane** (`apps/<product>/` is where per-user
  Google app data — Drive today, Gmail/Calendar later — lives).

## Modules

| Module | Category | API | Enumerates / does | Tables |
| --- | --- | --- | --- | --- |
| `enum_cloud_identity` | enum | Cloud Identity | users, groups, group memberships | `workspace_users`, `workspace_groups`, `workspace_group_memberships` |
| `enum_admin_roles` | enum | Directory | admin roles + role assignments (flags super-admins) | `workspace_admin_roles`, `workspace_role_assignments` |
| `enum_org_units` | enum | Directory | organizational units | `workspace_org_units` |
| `enum_domains` | enum | Directory | tenant domains | `workspace_domains` |
| `enum_mobile_devices` | enum | Directory | enrolled mobile devices | `workspace_mobile_devices` |
| `enum_oauth_tokens` | enum | Directory | per-user 3rd-party OAuth app grants | `workspace_oauth_tokens` |
| `enum_group_settings` | enum | Groups Settings | per-group access/posting (flags self-join-open) | `workspace_group_settings` |
| `enum_data_transfers` | enum | Data Transfer | data-transfer requests | `workspace_data_transfers` |
| `enum_drive` | enum | Drive v3 | a user's Drive files + ACL exposure, + optional content download (`--download`/`--download-public`; logged, 3 tiers) | `workspace_drive_files`, `workspace_drive_permissions` (downloads to `downloads/`) |

`enum_google_workspace` runs the tenant-scoped enum modules **once**. `enum_drive`
is **not** in that sweep — it is per-user and can be large, so run it explicitly
(`--caller-email <user>` or `--all-users`). The top-level `enum_all` runs the GCP
per-project sweep **and then** a single post-GCP Workspace phase; `enum_gcp`
is GCP-only (no Workspace phase).

## Credentials (important)

**GCP credentials do not grant Workspace access.** Supported paths:

1. **Admin user credential** — required scopes attach automatically.
2. **Service account + domain-wide delegation (DWD)** — the SA impersonates an
   admin via `creds.with_subject(admin@domain)`. The SA's OAuth **client ID**
   must be authorized in the Workspace **Admin console** (done outside gcpwn);
   gcpwn only needs the **subject** (admin email) — pass `--impersonate
   <admin@domain>` or set it once with `configs set workspace_admin_subject`.
3. **A Workspace user's own OAuth credential** — for a user that has *no GCP
   access at all* (e.g. a Workspace-only super-admin). Google has **no
   username/password API** (no ClientLogin/ROPC), so you cannot exchange an
   email+password for a token programmatically (a built-in `creds login` browser
   flow is planned but not currently shipped). Instead, load a pre-obtained token:
   - `creds add <name> --type oauth2 --token-file token.json` — a token.json you
     minted elsewhere (e.g. `gcloud auth application-default login`); carries a
     refresh token, auto-renews.
   - `creds add <name> --type oauth2 --token <access_token>` — a bare access token
     (expires in ~1h, no refresh).

   Whatever scopes the token was consented with are what you get — grant the Drive
   / Directory / Groups scopes up front if you plan to run those modules.

### Drive scopes (per-user data plane)

`enum_drive` read a **user's Drive**, so with a service
account you impersonate the *target user* directly (`--caller-email` is the DWD
subject; `--all-users` sweeps `workspace_users`). Add
`https://www.googleapis.com/auth/drive.readonly` to the DWD grant (or the user
token's scopes) and enable the **Drive API** in the SA's GCP project; without the
scope the module reports a clear "access denied — check scopes/DWD" and stops.

Directory modules also need a **directoryCustomerId**, resolved (and cached) in
order: `--customer-id` → `configs set workspace_customer_id` → derived from the
GCP organization (`--org-id`, or the cached hierarchy). Common flags across the
directory modules: `--customer-id`, `--org-id`, `--impersonate`,
`--directory-customer`.

## OpenGraph integration

The `workspace_*` tables feed OpenGraph (all **add-only** — with no Workspace data
the graph is byte-identical to a GCP-only graph):

- users/groups → `GoogleUser` / `GoogleGroup` nodes with `GOOGLE_MEMBER_OF` edges;
- each Workspace **super-admin** → `CAN_IMPERSONATE` / `CAN_RESET_PASSWORD` edges
  to every other user;
- a service account with **domain-wide delegation** → a `GoogleWorkspaceTenant`
  hub node + `DOMAIN_WIDE_DELEG` edges to every user it can impersonate (a
  GCP→Workspace takeover path invisible to normal IAM enumeration);
- **self-join-open groups** → `CAN_JOIN` edges from `GCPAllUsers` (anyone-can-join)
  or a per-tenant `PrincipalsInOrg` node (all-in-domain-can-join);
- **public / anyone-with-link Drive files** → a `GoogleDriveFile` node + a
  `CAN_READ` edge from `GCPAllUsers`.

OpenGraph output is a golden-tested contract; do not change emitted node/edge
shapes without updating the golden tests.

## Coming soon (not yet implemented)

- More per-user data planes under `apps/` (Gmail / Calendar sharing & exposure).
- Deeper Workspace → GCP OpenGraph bridging beyond super-admin impersonation
  (e.g. group-based IAM inheritance paths surfaced as first-class edges).
