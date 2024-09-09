# WebbinRoot TODO add a throttling mechanism
# All credit to https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/gcpbucketbrute.py
from Modules.CloudStorage.utils.util_helpers import *
import sys, multiprocessing
from datetime import datetime, timedelta

def outprint(data='', file_path='', normal_print=''):
    with open(file_path, 'a+') as f:
        f.write('{}\n'.format(data))

    normal_print(data)

def generate_bucket_permutations(keyword, all_tlds = False):
    permutation_templates = [
        '{keyword}-{permutation}',
        '{permutation}-{keyword}',
        '{keyword}_{permutation}',
        '{permutation}_{keyword}',
        '{keyword}{permutation}',
        '{permutation}{keyword}'
    ]
    with open('./Modules/CloudStorage/utils/gcpbucketbrute_permutations.txt', 'r') as f:
        permutations = f.readlines()
        buckets = []
        for perm in permutations:
            perm = perm.rstrip()
            for template in permutation_templates:
                generated_string = template.replace('{keyword}', keyword).replace('{permutation}', perm)
                buckets.append(generated_string)

    buckets.append(keyword)
    if all_tlds:
        # Added by WebbinRoot, lets just try every TLD ;)
        with open('./Modules/CloudStorage/utils/top_level_domains.txt', 'r') as f:
            tlds = f.readlines()
            for tld in tlds:
                tld = tld.strip().lower()
                buckets.append('{}.{}'.format(keyword,tld))
    else:
        buckets.append('{}.com'.format(keyword))
        buckets.append('{}.net'.format(keyword))
        buckets.append('{}.org'.format(keyword))

    buckets = list(set(buckets))

    # Strip any guesses less than 3 characters or more than 63 characters
    final_bucket_list = []
    for bucket in buckets:
        if not (len(bucket) < 3 or len(bucket) > 63):
            final_bucket_list.append(bucket)
    
    print('\nGenerated {} bucket permutations.\n'.format(len(final_bucket_list)))
    return final_bucket_list

def read_wordlist(filename):
    try:
        file = open(filename, 'r')
        lines = file.read().splitlines()
        file.close()
        return lines
    except FileNotFoundError:
        print(f'Error: File {filename} not found')
        exit(1)
    except PermissionError:
        print('Error: Permission denied')
        exit(1)

# Entrypoint
def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate Buckets Options")
    
    # Debug/non-module specific
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")
    parser.add_argument('--authenticated', action="store_true", help='Try to check permissions of bucket as authenticate user. Note this might log your credentials in the impacted bucket.')
    parser.add_argument('--all-tlds', action="store_true", required=False, default=None, help='Try every possible TLD domain (will take longer)')
    parser.add_argument('--throttle', type=int, required=False, default=None, help='Number of seconds to throttle each request, note it will send all subprocess requests at once than sleep.')


    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', required=False, action="append", help='Check a single bucket name instead of bruteforcing names based on a keyword. May be repeated to check multiple buckets.')
    group.add_argument('--check-list', required=False, default=None, help='Check a list of buckets in the given file, one per line.')

    group.add_argument('-k', '--keyword', required=False, help='The base keyword to use when guessing bucket names. This could be a simple string like "Google" or a URL like "google.com" or anything else. This string is used to generate permutations to search for.')
    group.add_argument('-w', '--wordlist', required=False, default=None, help='The path to a wordlist file')
    parser.add_argument('-s', '--subprocesses', required=False, default=5, type=int, help='The amount of subprocesses to delegate work to for enumeration. Default: 5. This is essentially how many threads you want to run the script with, but it is using subprocesses instead of threads.')
    # add later check code was causing issues
    parser.add_argument('-o', '--out-file', required=False, default=None, help='The path to a log file to write the scan results to. The file will be created if it does not exist and will append to it if it already exists. By default output will only print to the screen.')
    
    args = parser.parse_args(user_args)
    
    # Only immplementing unauthetnicated right now
    client = None
    if args.authenticated:
        accept_auth = session.choice_prompt("You chose to do an authenticate permissions check if a bucket is found. Note this will use the current set of GCP credentials. Note this could log your username in the specified account. If this is  intended and you meant to use the --authenticate flag, type Y: ")
        if accept_auth.strip() == "Y":
            client = storage.Client(credentials = session.credentials, project = session.project_id) 
        else:
            print("Please try again. Exiting current run...")
            return -1

    debug = args.debug

    subprocesses = []
    if args.keyword:
        buckets = generate_bucket_permutations(args.keyword, all_tlds = args.all_tlds)
    elif args.wordlist:
        buckets = read_wordlist(args.wordlist)
    
    # manual check of bucket names
    elif args.check:
        buckets = args.check
    elif args.check_list:
        with sys.stdin if args.check_list == '-' else open(args.check_list, 'r') as fd:
            buckets = fd.read().splitlines()

    start_time = time.time()

    for i in range(0, args.subprocesses):
        start = int(len(buckets) / args.subprocesses * i)
        end = int(len(buckets) / args.subprocesses * (i+1))
        permutation_list = buckets[start:end]
        subproc = Worker(client,permutation_list, args.authenticated, throttle = args.throttle, debug = args.debug)
        subprocesses.append(subproc)
        subproc.start()

    cancelled = False
    while len(subprocesses) > 0:
        try:
            subprocesses = [s.join() for s in subprocesses if s is not None]
        except KeyboardInterrupt:
            cancelled = True
            print('Ctrl+C pressed, killing subprocesses...')

    if not cancelled:
        end_time = time.time()
        scanning_duration = timedelta(seconds=(end_time - start_time))
        d = datetime(1, 1, 1) + scanning_duration

        if d.day - 1 > 0:
            print('\nScanned {} potential buckets in {} day(s), {} hour(s), {} minute(s), and {} second(s).'.format(len(buckets), d.day-1, d.hour, d.minute, d.second))
        elif d.hour > 0:
            print('\nScanned {} potential buckets in {} hour(s), {} minute(s), and {} second(s).'.format(len(buckets), d.hour, d.minute, d.second))
        elif d.minute > 0:
            print('\nScanned {} potential buckets in {} minute(s) and {} second(s).'.format(len(buckets), d.minute, d.second))
        else:
            print('\nScanned {} potential buckets in {} second(s).'.format(len(buckets), d.second))

    print('\nGracefully exiting!')
 

class Worker(multiprocessing.Process):
    def __init__(self, client, permutation_list, authenticated, throttle = None, debug=False):
        multiprocessing.Process.__init__(self)
        self.client = client
        self.throttle = throttle
        self.permutation_list = permutation_list
        #self.out_file = out_file
        self.debug = debug
        self.authenticated = authenticated
    
    def update_status_bar(self,current_string):
        print(f"Checking: {current_string}", end='\r')
        # Simulate some processing time

    def run(self):
        try:
            for bucket_name in self.permutation_list:

                self.update_status_bar(bucket_name)
                #if self.debug:
                    #print(f"[DEBUG] Trying bucket {bucket_name}")
                if check_existence(bucket_name):
                    if self.debug:
                        print(f"[DEBUG] Bucket {bucket_name} exists, trying permission checks")
                        print("[DEBUG] Unauthenticated: {}".format(str(True)))
                        print("[DEBUG] Authenticated: {}".format(str(self.authenticated)))
                    check_bucket_permissions(self.client, bucket_name, gcpbucketbrute = True, authenticated = self.authenticated, unauthenticated = True, debug = self.debug)
                if self.throttle:
                    time.sleep(self.throttle)
        except KeyboardInterrupt:
            return