from typing import List, Union, Dict, Optional, Tuple
import hashlib, hmac, textwrap
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import importlib

import xml.etree.ElementTree as ET

# Typing libraries
from session import SessionUtility
from google.cloud.storage.client import Client
from google.cloud.storage.blob import Blob
from google.cloud.storage.bucket import Bucket
from google.cloud.storage.hmac_key import HMACKeyMetadata

from Modules.IAM.utils.util_helpers import bucket_get_iam_policy,bucket_set_iam_policy

import base64, json
import os, requests, argparse, time, re
from UtilityController import *

from google.cloud import storage
from google.cloud.storage.hmac_key import *
from google.api_core.iam import Policy

from google.api_core.exceptions import PermissionDenied
from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from google.api_core.exceptions import BadRequest


########### SAVE OPERATIONS FOR OBJECTS/BLOBS

# Create bustom blob object for XML so I can set data via "." notation and keep same code
class CustomBucketObject:
    def __init__(self, dictionary: dict):
        for key, value in dictionary.items():
            setattr(self, key, value)

class CustomBlobObject:
    def __init__(self, dictionary: dict):
        for key, value in dictionary.items():
            setattr(self, key, value)

def save_bucket_xml(bucket: CustomBucketObject, session: SessionUtility) -> None:
    table_name = 'cloudstorage-buckets'

    save_data = { "project_id" : session.project_id }
    if bucket.name: save_data["name"] = bucket.name
    if bucket.time_created: save_data["time_created"] = bucket.time_created

    # Only insert XMl data if the bucket doesn't already exist
    session.insert_data(table_name, save_data, only_if_new_columns = ["name"])

def save_blob_xml(blob: CustomBlobObject, session: SessionUtility) -> None:
    table_name = 'cloudstorage-bucketblobs'
    
    save_data = { "project_id" : session.project_id }
    if blob.name: save_data["name"] = blob.name
    if blob.size: save_data["size"] = blob.size
    if blob.updated: save_data["updated"] = blob.updated
    if blob.generation: save_data["generation"] = blob.generation
    if blob.metageneration: save_data["metageneration"] = blob.metageneration
    if blob.etag: save_data["etag"] = blob.etag
    if blob.bucket_name: save_data["bucket_name"] = blob.bucket_name

    # Only insert XMl data if the blob name does not exist
    session.insert_data(table_name, save_data, only_if_new_columns = ["project_id", "name"])

def save_bucket(bucket: storage.Bucket, session: SessionUtility) -> None:
    table_name = 'cloudstorage-buckets'

    save_data = { "project_id" : session.project_id }
    if bucket.id: save_data["id"] = bucket.id
    if bucket.name: save_data["name"] = bucket.name
    if bucket.storage_class: save_data["storage_class"] = bucket.storage_class
    if bucket.location: save_data["location"] = bucket.location
    if bucket.location_type: save_data["location_type"] = bucket.location_type
    if bucket.cors: save_data["cors"] = bucket.cors
    if bucket.default_event_based_hold: save_data["default_event_based_hold"] = bucket.default_event_based_hold
    if bucket.default_kms_key_name: save_data["default_kms_key_name"] = bucket.default_kms_key_name
    if bucket.metageneration: save_data["metageneration"] = bucket.metageneration
    if bucket.iam_configuration.public_access_prevention: save_data["iam_configuration_public_access_prevention"] = bucket.iam_configuration.public_access_prevention
    if bucket.retention_policy_effective_time: save_data["retention_policy_effective_time"] = bucket.retention_policy_effective_time
    if bucket.retention_period: save_data["retention_period"] = bucket.retention_period
    if bucket.retention_policy_locked: save_data["retention_policy_locked"] = bucket.retention_policy_locked
    if bucket.requester_pays: save_data["requester_pays"] = bucket.requester_pays
    if bucket.self_link: save_data["self_link"] = bucket.self_link
    if bucket.time_created: save_data["time_created"] = bucket.time_created 
    if bucket.versioning_enabled: save_data["versioning_enabled"] = bucket.versioning_enabled
    if bucket.labels: save_data["labels"] = bucket.labels


    session.insert_data(table_name, save_data)


def save_blob(blob: storage.Blob, session: SessionUtility) -> None:
    table_name = 'cloudstorage-bucketblobs'
    
    save_data = { "project_id" : session.project_id }
    if blob.name: save_data["name"] = blob.name
    if blob.bucket and blob.bucket.name: save_data["bucket_name"] = blob.bucket.name
    if blob.storage_class: save_data["storage_class"] = blob.storage_class
    if blob.id: save_data["id"] = blob.id
    if blob.size: save_data["size"] = blob.size
    if blob.updated: save_data["updated"] = blob.updated
    if blob.generation: save_data["generation"] = blob.generation
    if blob.metageneration: save_data["metageneration"] = blob.metageneration
    if blob.etag: save_data["etag"] = blob.etag
    if blob.owner: save_data["owner"] = blob.owner
    if blob.component_count: save_data["component_count"] = blob.component_count
    if blob.crc32c: save_data["crc32c"] = blob.crc32c
    if blob.md5_hash: save_data["md5_hash"] = blob.md5_hash
    if blob.cache_control: save_data["cache_control"] = blob.cache_control
    if blob.content_type: save_data["content_type"] = blob.content_type
    if blob.content_disposition: save_data["content_disposition"] = blob.content_disposition
    if blob.content_encoding: save_data["content_encoding"] = blob.content_encoding
    if blob.content_language: save_data["content_language"] = blob.content_language
    if blob.metadata: save_data["metadata"] = blob.metadata
    if blob.media_link: save_data["media_link"] = blob.media_link
    if blob.custom_time: save_data["custom_time"] = blob.custom_time
    if blob.temporary_hold: save_data["temporary_hold"] = "enabled" if blob.temporary_hold else "disabled"
    if blob.event_based_hold: save_data["event_based_hold"] = "enabled" if blob.event_based_hold else "disabled"
    if blob.retention_expiration_time: save_data["retention_expiration_time"] = blob.retention_expiration_time
    session.insert_data(table_name, save_data)

def save_hmac_key(key: HMACKeyMetadata, session: SessionUtility, secret: Optional[str] = None, dont_change: Optional[List[str]] = None) -> None:
    table_name = 'cloudstorage-hmac-keys'

    save_data = {}
    if secret: save_data["secret"] = secret
    if key.access_id: save_data["access_id"] = key.access_id
    if key.etag: save_data["etag"] = key.etag
    if key.id: save_data["id"] = key.id
    if key.path: save_data["path"] = key.path
    if key.project: save_data["project_id"] = key.project
    if key.service_account_email: save_data["service_account_email"] = key.service_account_email
    if key.state: save_data["state"] = key.state
    if key.time_created: save_data["time_created"] = key.time_created
    if key.updated: save_data["updated"] = key.updated
    if key.user_project: save_data["user_project"] = key.user_project
    session.insert_data(table_name, save_data, dont_change = dont_change)
     
########### TestIAMPermissions Checks

# client can be None if only unauth per GCPBucketBrute
# Note nicely formatted output is taken from GCPBucketBrute here: https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/gcpbucketbrute.py
def check_bucket_permissions(client: Union[Client, None], bucket_name:str, gcpbucketbrute: Optional[bool] = False, authenticated: Optional[bool] = False, unauthenticated: Optional[bool] = False, debug: Optional[bool] = False) -> Tuple[List, List]:
    

    authenticated_permissions, unauthenticated_permissions = [], []
    
    if client and authenticated:
        
        try:

    
                authenticated_permissions = client.bucket(bucket_name).test_iam_permissions(
                    permissions=[
                        'storage.buckets.delete',
                        'storage.buckets.get',
                        'storage.buckets.getIamPolicy',
                        'storage.buckets.setIamPolicy',
                        'storage.buckets.update',
                        'storage.objects.create',
                        'storage.objects.delete',
                        'storage.objects.get',
                        'storage.objects.list',
                        'storage.objects.update'
                    ]
                )



        except NotFound as e:

            print(f"[-] 404  {bucket_name} does not appear to exist ")
            authenticated_permissions = []

        except Forbidden as e:

            print(f"[-] 403 Bucket Exists, but the user does not have storage.testIamPermissions permissions on bucket {bucket_name} ")
            authenticated_permissions = []

        except Exception as e:
            
            print(f"[-] 403 TestIAMPermissions failed for {bucket_name} for the following reason:\n"+str(e))
            authenticated_permissions = []            

        if gcpbucketbrute and authenticated_permissions:
                print('\n    AUTHENTICATED ACCESS ALLOWED: {}'.format(bucket_name))
                if 'storage.buckets.setIamPolicy' in authenticated_permissions:
                    print('        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)')
                if 'storage.objects.list' in authenticated_permissions:
                    print('        - AUTHENTICATED LISTABLE (storage.objects.list)')
                if 'storage.objects.get' in authenticated_permissions:
                    print('        - AUTHENTICATED READABLE (storage.objects.get)')
                if 'storage.objects.create' in authenticated_permissions or 'storage.objects.delete' in authenticated_permissions or 'storage.objects.update' in authenticated_permissions:
                    print('        - AUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)')
                print('        - ALL PERMISSIONS:')
                print(textwrap.indent('{}\n'.format(json.dumps(authenticated_permissions, indent=4)), '        '))
        elif gcpbucketbrute:
            print('\n    NO AUTHENTICATED ACCESS ALLOWED')

    if unauthenticated:
        
        unauth_url = 'https://www.googleapis.com/storage/v1/b/{}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update'.format(bucket_name)


        unauthenticated_permissions_request = requests.get(unauth_url).json()

        unauthenticated_permissions = []
        
        if unauthenticated_permissions_request.get('permissions'):

            unauthenticated_permissions = unauthenticated_permissions_request['permissions']

            if gcpbucketbrute:
                print('\n    UNAUTHENTICATED ACCESS ALLOWED: {}'.format(bucket_name))
                if 'storage.buckets.setIamPolicy' in unauthenticated_permissions:
                    print('        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)')
                if 'storage.objects.list' in unauthenticated_permissions:
                    print('        - UNAUTHENTICATED LISTABLE (storage.objects.list)')
                if 'storage.objects.get' in unauthenticated_permissions:
                    print('        - UNAUTHENTICATED READABLE (storage.objects.get)')
                if 'storage.objects.create' in unauthenticated_permissions or 'storage.objects.delete' in unauthenticated_permissions or 'storage.objects.update' in unauthenticated_permissions:
                    print('        - UNAUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)')
                print('        - ALL PERMISSIONS:')
                print(textwrap.indent('{}\n'.format(json.dumps(unauthenticated_permissions, indent=4)), '            '))

        if gcpbucketbrute and not (authenticated_permissions or unauthenticated_permissions):
            print('    EXISTS: {}'.format(bucket_name))
        
    return authenticated_permissions, unauthenticated_permissions

########### Retrieve Data

def list_buckets(storage_client: Client, debug: Optional[bool] = False)-> Union[List, None]:
    
    if debug:
        print(f"[DEUBG] Getting buckets...")

    bucket_list = None

    try:

        # Will not trigger permission error till used
        buckets = storage_client.list_buckets()

        # Convert Iterator to List, will trigger error if permission denied was respnose
        bucket_list = list(buckets)


    except NotFound as e:
        if "The requested project was not found" in str(e):
            print(f"{UtilityTools.RED}[X] The project could not be used. It might be in a deleted state or not exist.{UtilityTools.RESET}")


    except Forbidden as e:
        if "does not have storage.buckets.list" in str(e):
            print(f"{UtilityTools.RED}[X] The user does not have storage.buckets.list permissions on bucket{UtilityTools.RESET}")
    
    except Exception as e:
        print(f"The storage.buckets.list operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successful completed list_buckets...")

    return bucket_list

def get_bucket(storage_client:Client, bucket_name:str, debug:Optional[bool] = False) -> Union[Bucket, None]:
    
    if debug:
        print(f"[DEBUG] Getting bucket metadata for {bucket_name} ...")

    bucket_meta = None

    try:

        bucket_meta = storage_client.get_bucket(bucket_name)

        
    except NotFound as e:
        print(f"{UtilityTools.RED}[X] 404 Bucket {bucket_name} was not found{UtilityTools.RESET}")

    except Forbidden as e:
        if "does not have storage.buckets.get access" in str(e):
            print(f"{UtilityTools.RED}[X] 403 The user does not have storage.buckets.get permissions on bucket {bucket_name}{UtilityTools.RESET}")

    except Exception as e:
        print("An unknown exception occurred when trying to call get_bucket as follows:\n" + str(e))

    if debug:
        print(f"[DEBUG] Successfully completed get_bucket ...")

    return bucket_meta

def list_blobs(storage_client: Client, bucket_name: str, debug: Optional[bool] =False)-> Union[List, None]:
    
    if debug:
        print(f"[DEBUG] Listing blobs for {bucket_name}")


    blob_list = None

    try:

        blobs = storage_client.list_blobs(bucket_name)

        blob_list = list(blobs)


    except NotFound as e:
        if "does not exist" in str(e):
            print(f"{UtilityTools.RED}[X] 404: Bucket {bucket_name} does not appear to exist when calling list objects{UtilityTools.RESET}")

    except Forbidden as e:
        if "does not have storage.objects.list" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have storage.objects.list permissions on{UtilityTools.RESET}")

    except Exception as e:
        print(f"The storage.objects.list operation failed for unexpected reasons for {project_id}:{bucket_name}. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successful completed list_blobs...")

    return blob_list

# Store action at bucket level instead of blob as that would be too much data
def get_blob(bucket: Bucket, blob_name: str, debug: Optional[bool] = False)-> Union[Blob, None]:

    if debug:
        print(f"[DEBUG] Getting blob meta {blob_name} for {bucket.name}")

    blob_meta = None

    try:

        blob_meta = bucket.get_blob(blob_name)

    except Forbidden as e:
        if "does not have storage.objects.get access" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have storage.objects.get permissions on blob {blob_name} for bucket {bucket.name}{UtilityTools.RESET}")
    
    except Exception as e:
        print(str(e))
        print("[DEBUG] UNKNOWN EXCEPTION WHEN GETTING BLOB DETAILS")

    if debug:
        print(f"[DEUBG] Successful completed get_blob...")

    return blob_meta


def list_hmac_keys(storage_client: Client, debug:Optional[bool] = False)-> Union[List, None]:
    
    if debug:
        print(f"[DEUBG] Listing HMAC keys...")

    keys = None

    try:

        # TODO documentation might be wrong but GCP says secret keys hould be returned here as well?
        # Will not trigger permission error till used
        keys = list(storage_client.list_hmac_keys(show_deleted_keys = True))

    except NotFound as e:
        if "The requested project was not found" in str(e):
            print(f"{UtilityTools.RED}[X] 404: The project could not be used. It might be in a deleted state or not exist.{UtilityTools.RESET}")

    except Forbidden as e:
        if "does not have storage.hmacKeys.list" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have storage.hmacKeys.list permissions on bucket{UtilityTools.RESET}")
    
    except Exception as e:
        print(f"The storage.hmacKeys.list operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successful completed list_hmac_keys...")

    return keys

def get_hmac_key(storage_client: Client, access_id:str, debug: Optional[bool] = False)-> Union[HMACKeyMetadata, None]:
    
    if debug:
        print(f"[DEUBG] Getting HMAC key {access_id}...")

    key = None

    try:
        # Will not trigger permission error till used
        key = storage_client.get_hmac_key_metadata(access_id)

    except Forbidden as e:
        if "does not have storage.hmacKeys.get" in str(e):
            print(f"{UtilityTools.RED}[X] The user does not have storage.hmacKeys.get permissions on bucket{UtilityTools.RESET}")
    
    except NotFound as e:
        if "Access ID not found in project" in str(e):
            print(f"{UtilityTools.RED}[X] The access ID does not appear to exist.{UtilityTools.RESET}")

    except Exception as e:
        print(f"The storage.hmacKeys.get operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successful completed get_hmac_key...")

    return key



########### Mutate Data

def upload_to_bucket(storage_client: Client, bucket_name: str, remote_path: str, local_blob_path: Optional[str] = None, data_string: Optional[str] = None, debug:Optional[bool] = False) -> Union[None, bool]:
    

    if debug:
        if local_blob_path:
            print(f"[DEBUG] Proceeding to upload {local_blob_path} to {bucket_name}/{remote_path} ...")
        elif data_string:
            print(f"[DEBUG] Proceeding to upload {data_string} to {bucket_name}/{remote_path} ...")

    try: 

        uploading_bucket = storage_client.bucket(bucket_name)
        uploading_blob = uploading_bucket.blob(remote_path)

        # Upload from local file
        if local_blob_path:
            uploading_blob.upload_from_filename(local_blob_path)
        
        # Upload from string
        elif data_string:
            uploading_blob.upload_from_string(data_string)
 
    except FileNotFoundError as e:
        if f"No such file or directory: '{local_blob_path}'" in str(e):
            print(f"{UtilityTools.RED}[X] File {local_blob_path} does not exist. Exiting...{UtilityTools.RESET}")
        return None

    except Forbidden as e:
        if "does not have storage.objects.create access to the Google Cloud Storage object" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have storage.objects.create permissions on project {project_id}{UtilityTools.RESET}" )
        return None

    except Exception as e:
        print("[X] The storage.objects.create API call failed for uknown reasons. See the error below:")
        print(str(e))
        return None

    if debug:
        print(f"[DEBUG] Completed upload_to_bucket")

    return True

def create_hmac_key(storage_client: Client, sa_email: str, debug: Optional[bool] = False) -> Union[Tuple[None, None], Tuple[str, HMACKeyMetadata]]:

    if debug:
        print(f"[DEUBG] Creating HMAC key for {sa_email}...")

    key, secret = None, None

    try:

        # Will not trigger permission error till used
        key, secret = storage_client.create_hmac_key(sa_email)
        
    except Forbidden as e:
        if "does not have storage.hmacKeys.create" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have storage.hmacKeys.create permissions on bucket{UtilityTools.RESET}")
    
    except Exception as e:
        print(f"The storage.hmacKeys.create operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successful completed create_hmac_key...")

    return (key, secret)


def update_hmac_key(storage_client: Client, access_id:str, stat:str, debug:Optional[bool]=False)-> Union[int, None]:


    if debug:
        print(f"[DEUBG] Updating HMAC key for {access_id}...")

    try:

        hmac_object = HMACKeyMetadata(storage_client, access_id = access_id)
        hmac_object.state = state
        hmac_object.update()
        
        return 1
        
    except Forbidden as e:
        if "does not have storage.hmacKeys.create" in str(e):
            print(f"403: {UtilityTools.RED}[X] The user does not have storage.hmacKeys.create permissions on bucket{UtilityTools.RESET}")
    
    except Exception as e:
        print(f"The storage.hmacKeys.create operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successful completed create_hmac_key...")

    return None

# Storage XML APIs: https://cloud.google.com/storage/docs/xml-api/overview

# Used source code form following sources to replicate SigV4 in native python
# - https://cloud.google.com/storage/docs/access-control/signed-urls
# - https://medium.com/@rosyparmar/google-cloud-storage-use-hmac-to-authenticate-requests-to-cloud-storage-aa8ed859be33
# - https://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-signing-requests.html#example-signature-calculation
# - https://stackoverflow.com/questions/13019203/how-can-i-calculate-an-aws-api-signature-v4-in-python
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
# - NOTE can do aws s3 --endpoint-url https://storage.googleapis.com ls s3://[bucket_name]  --profile gcp  --no-verify-ssl 
def get_signature(secret_key, date_stamp, region, service):
    key = ('AWS4' + secret_key).encode('utf-8')
    date_key = hmac.new(key, date_stamp.encode('utf-8'), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode('utf-8'), hashlib.sha256).digest()
    service_key = hmac.new(region_key, service.encode('utf-8'), hashlib.sha256).digest()
    signing_key = hmac.new(service_key, b'aws4_request', hashlib.sha256).digest()
    return signing_key

def calculate_final_hash(secret_key, date_stamp, region, service, string_to_sign):
    signing_key = get_signature(secret_key, date_stamp, region, service)
    return hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def sign_request(access_id, secret_key, region, service, method, url, headers, payload, sha256_header = None):

    # Step 0: Calculate Date and add to headers for later signing
    request_datetime = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    datestamp = f'{request_datetime[:8]}'
    headers["X-Amz-Date"] = request_datetime
    
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    headers["X-Amz-Content-Sha256"] = payload_hash


    # Step 1: Get Payload Hash
    parsed_url = urlparse(url)

    query_params = parse_qs(parsed_url.query)
    if not query_params:
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
        # If the URI does not include a '?', there is no query string in the request, 
        # and you set the canonical query string to an empty string ("")
        canonical_query = ""
    
    domain = parsed_url.netloc
    path = parsed_url.path

    if path == "/":
        canonical_uri = "/"
    elif "?" in path:
        canonical_uri = path.split("?")[0]
    else:
        canonical_uri = path
    canonical_headers = []
    for header, value in sorted(headers.items()):
        canonical_header = f"{header.lower().strip()}:{' '.join(value.strip().split())}\n"
        canonical_headers.append(canonical_header)
    canonical_headers = ''.join(canonical_headers)

    signed_headers = ';'.join(sorted(header.lower().strip() for header in headers))
    
    # Create Canonical request String and Hahs of Canonical string
    canonical_request = "\n".join([method,canonical_uri,canonical_query,canonical_headers,signed_headers,payload_hash ])
    
   
    # Step 3: Create "string-to-sign"
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f'{datestamp}/{region}/{service}/aws4_request'
    hashed_canonical_request = hashlib.sha256(canonical_request.encode()).hexdigest()
    string_to_sign = "\n".join([algorithm, request_datetime, credential_scope, hashed_canonical_request])
    
    # Step 4 Calculate Signature [Verified this is 100% correct] with
    signature = calculate_final_hash(secret_key, datestamp, "us-central1", "s3", string_to_sign)

    # Add signature and all components for final Authorization header
    final_authorization_header = f"{algorithm} Credential={access_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    headers["Authorization"] = final_authorization_header

    return headers

def hmac_list_buckets(storage_client, access_id, secret, project_id, debug=False):
    

    if project_id == None:
        project_id = ""
    all_buckets = None

    try:
        access_key = access_id
        secret_key = secret
        region = 'us-central1' # Misc doesn't matter here for compatiblity sake
        service = 's3' 
        method = "GET"
        url = 'https://storage.googleapis.com/'
        header_to_sign = {
            'Host': 'storage.googleapis.com',
            'X-Amz-Project-Id': project_id
        }
        payload = ''  # Request payload
        signed_headers = sign_request(access_key, secret_key, region, service, method, url, header_to_sign, payload)
      
        # Send the request using the requests library
        response = requests.get(url, headers=signed_headers,  verify = False)
        
        
        root = ET.fromstring(response.text)
        
        buckets = []
        for element in root.iter():
            if element.tag.endswith('Bucket'):
                buckets.append(element)

  
        all_buckets = []
  
        for bucket in buckets:
            name = None
            creation_date = None
            
            # Iterate over the child elements of the Bucket
            for child in bucket:
                # Check if the child element is Name
                if child.tag.endswith('Name'):
                    bucket_name = child.text
                # Check if the child element is CreationDate
                elif child.tag.endswith('CreationDate'):
                    bucket_creation_date = child.text

            bucket_dictionary = {

                "name": bucket_name,
                "time_created": bucket_creation_date
            }

            bucket_object = CustomBucketObject(bucket_dictionary)

            all_buckets.append(bucket_object)

    except Exception as e:
        print("[X] Failed to list buckets via XML API for following reason:")
        print(str(e))
    
    return all_buckets


def hmac_list_blobs(storage_client, access_id, secret, bucket_name, project_id, debug=False):
    

    if project_id == None:
        project_id = ""
    blobs_list = None
    bucket = storage_client.bucket(bucket_name)
    try:
        access_key = access_id
        secret_key = secret
        region = 'us-central1' # Misc doesn't matter here for compatiblity sake
        service = 's3' 
        method = "GET"
        url = f'https://storage.googleapis.com/{bucket_name}'
        header_to_sign = {
            'Host': f'storage.googleapis.com',
            'X-Amz-Project-Id': project_id
        }
        payload = ''  # Request payload
        signed_headers = sign_request(access_key, secret_key, region, service, method, url, header_to_sign, payload)
      
        # Send the request using the requests library
        response = requests.get(url, headers=signed_headers, verify = False)
       

        root = ET.fromstring(response.text)
        blobs = []
        for element in root.iter():
            if element.tag.endswith('Contents'):
                blobs.append(element)

        blobs_list = []
        for blob in blobs:
            blob_name, blob_size, blob_last_modified, blob_generation, blob_meta_generation, blob_etag =  None, None, None, None, None, None
            
            # Iterate over the child elements of the Bucket
            for child in blob:

                if child.tag.endswith('Key'):
                    blob_name = child.text
                elif child.tag.endswith('Size'):
                    blob_size = child.text
                elif child.tag.endswith('LastModified'):
                    blob_last_modified = child.text
                elif child.tag.endswith('Generation'):
                    blob_generation = child.text
                elif child.tag.endswith('MetaGeneration'):
                    blob_meta_generation = child.text
                elif child.tag.endswith('ETag'):
                    blob_etag = child.text


            blob_representation = {
                "name": blob_name,
                "size": blob_size,
                "updated": blob_last_modified,
                "generation":blob_generation.replace("\"",""),
                "metageneration": blob_meta_generation,
                "etag":blob_etag,
                "bucket_name": bucket_name
            }
            blob_object =CustomBlobObject(blob_representation)
            blobs_list.append(blob_object)


    except Exception as e:
        print("[X] Failed to get bucket via XML API for following reason:")
        print(str(e))
    
    return blobs_list

# TODO in progress
def hmac_upload_to_bucket(bucket_name, local_blob_path, remote_blob_path, debug=None):
    

    project_id = ""

    try:

        access_key = access_id
        secret_key = secret_key
        region = 'us-central1' # Misc doesn't matter here for compatiblity sake
        service = 's3' 
        method = "GET"
        url = f'https://storage.googleapis.com/{bucket_name}/{blob_name}'
        header_to_sign = {
            'Host': f'storage.googleapis.com',
            'X-Amz-Project-Id': project_id
        }
        payload = ''  # Request payload
        signed_headers = sign_request(access_key, secret_key, region, service, method, url, header_to_sign, payload)
      
        # Send the request using the requests library
        response = requests.get(url, headers=signed_headers,  verify = False)
        print(response.text)

    except Exception as e:
        print("[X] Failed to upload blob via XML API for following reason:")
        print(str(e))
    

def download_blob(storage_client, bucket, blob,project_id, debug=False, output_folder = None, user_regex_pattern  = None, blob_size_limit = None):
    
    bucket_name = bucket.name
    blob_name = blob.name
    blob_size = blob.size

    # If either a regex pattern and blob size are not set, or the regex pattern matches and/or the blob size matches, download file
    if (user_regex_pattern == None or re.search(user_regex_pattern,blob_name)) and (blob_size_limit == None or blob_size <=blob_size_limit):
       
                
        if debug:
            print(f"[DEBUG] Downloading blob {blob_name}...")

        # Let user set output folder here if they don't want to use default first_directory
        first_directory = output_folder + "/REST"

        # Store data in project folder in bucket folder
        if project_id:
            directory_to_store = f"{first_directory}/{project_id}/{bucket_name}/"
        else:
            directory_to_store = f"{first_directory}/Unknown/{bucket_name}/"

        os.makedirs(directory_to_store, exist_ok=True)

        # If blob is a directory, don't download but make directory to prepare for eventual download
        if "/" in blob_name:
            extra_dirs = "/".join(blob_name.split("/")[:-1])
            final_folder = directory_to_store+extra_dirs
            if not os.path.exists(final_folder):
                os.makedirs(final_folder, exist_ok=True)

        # blob name download should work as folders have been created
        destination_filename = directory_to_store + blob_name
        if destination_filename[-1] != "/":

            try:

                blob.download_to_filename(destination_filename)


            except Forbidden as e:
                if "storage.objects.get" in str(e):
                    print(f"[-] The user could not download {blob_name}")   

            except Exception as e:
                if project_id:
                    print(f"The storage.objects.get operation failed for unexpected reasons for {project_id}:{bucket_name}. See below:")
                else:
                    print(f"The storage.objects.get operation failed for unexpected reasons for {bucket_name}. See below:")
                print(str(e))

def hmac_download_blob(storage_client,access_id, secret_key, bucket_name, blob_name,project_id, debug=False, output_folder = None):
    
    
    if project_id == None:
        project_id = ""
    
    try:

        first_directory = output_folder + "/XML"

        # Store data in project folder in bucket folder
        directory_to_store = f"{first_directory}/{project_id}/{bucket_name}/"

        os.makedirs(directory_to_store, exist_ok=True)

        # If blob is a directory, don't download but make directory to prepare for eventual download
        if "/" in blob_name:
            extra_dirs = "/".join(blob_name.split("/")[:-1])
            final_folder = directory_to_store+extra_dirs
            if not os.path.exists(final_folder):
                os.makedirs(final_folder, exist_ok=True)

        # blob name download should work as folders have been created
        destination_filename = directory_to_store + blob_name
        if destination_filename[-1] != "/":

            access_key = access_id
            secret_key = secret_key
            region = 'us-central1' # Misc doesn't matter here for compatiblity sake
            service = 's3' 
            method = "GET"
            url = f'https://storage.googleapis.com/{bucket_name}/{blob_name}'
            header_to_sign = {
                'Host': f'storage.googleapis.com',
                'X-Amz-Project-Id': project_id
            }
            payload = ''  # Request payload
            signed_headers = sign_request(access_key, secret_key, region, service, method, url, header_to_sign, payload)
          
            # Send the request using the requests library
            response = requests.get(url, headers=signed_headers, verify = False)
            
            with open(destination_filename, "w") as output_file:
                
                output_file.write(response.text)

    except Exception as e:
        print("[X] Failed to download blob via XML API for following reason:")
        print(str(e))


### Set IAM Policy

def add_bucket_iam_member(
        storage_client: Client, 
        bucket_name: Bucket, 
        member: str, 
        bucket_project_id: str, 
        action_dict: dict, 
        brute: Optional[bool] = False, 
        role: Optional[str] = None, 
        debug: Optional[bool] =False
    ):

    additional_bind = {"role": role, "members": [member]}
   
    print(f"[*] Adding {member} to {bucket_name}")
    policy = bucket_get_iam_policy(storage_client, bucket_name, debug=debug)

    if policy:
        action_dict.setdefault(bucket_project_id, {}).setdefault("storage.buckets.getIamPolicy", {}).setdefault("buckets", set()).add(bucket_name)
        policy.bindings.append(additional_bind)
        print(f"[*] New policy below being added to {bucket_name} \n{policy.bindings}")

    else:

        # Could not retrieve policy to append, rewrite entire policy?
        if brute:
            print(f"[-] Could not call get_iam_policy for {bucket_name}.")
            
            policy = Policy()
            additional_bind = [{"role": role, "members": [member]}]
            policy.bindings = additional_bind
            policy.version = 3

            print(f"[*] New policy below being added to {bucket_name} \n{policy.bindings}")
        
        else:

            print(f"[X] Exiting the module as we cannot append binding to existing bindings. Supply --brute to OVERWRITE (as opposed to append) IAM policy of the bucket to just your member and role")
            return -1
    status = bucket_set_iam_policy(storage_client, bucket_name, policy, debug=debug)
    if status:
        action_dict.setdefault(bucket_project_id, {}).setdefault("storage.buckets.setIamPolicy", {}).setdefault("buckets", set()).add(bucket_name)
    
    return status

########### Uitlity Checks

def get_all_hmac_secrets(session: SessionUtility, debug:Optional[bool]=False) -> Union[List, None]:

    rows_returned = session.get_data("cloudstorage-hmac-keys", columns = ["access_id", "secret", "service_account_email"], conditions = "secret != \"\"")
    if rows_returned:
        return rows_returned
    else:
        return None

# Taken from Rhino Security, see Unauthenticated/README.md: 
#     - https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/gcpbucketbrute.py 
def check_existence(bucket_name: str, debug=False) -> bool:
    # Check if bucket exists before trying to TestIamPermissions on it
    if debug:
        bucket_url = 'https://www.googleapis.com/storage/v1/b/{}'.format(bucket_name)
        print(f"[DEBUG] Checking {bucket_url}")
    response = requests.head('https://www.googleapis.com/storage/v1/b/{}'.format(bucket_name))
    if response.status_code not in [400, 404]:
        print(f"[*] Bucket {bucket_name} appears to exist with status code {response.status_code}")
        return True
    if debug:
        print(f"[DEBUG] Bucket {bucket_name} returned {response.status_code}. Does not exist.")
    return False

