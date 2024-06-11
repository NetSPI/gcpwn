from Modules.CloudFunctions.utils.util_helpers import *
import multiprocessing
import textwrap
from datetime import datetime, timedelta

def outprint(data='', file_path='', normal_print=''):
    with open(file_path, 'a+') as f:
        f.write('{}\n'.format(data))

    normal_print(data)

def generate_function_permutations(project, region = None):
    v1_regions = [line.strip() for line in open('Modules/CloudFunctions/utils/regions_v1.txt')]
    v2_regions = [line.strip() for line in open('Modules/CloudFunctions/utils/regions_v2.txt')]
    all_regions = set([])
    all_regions.update(v1_regions)
    all_regions.update(v2_regions)
    functions_urls = []
    if region:
        function_url = f"https://{region}-{project}.cloudfunctions.net/"
        functions_urls.append(function_url)
    else:
        for region in all_regions:
            function_url = f"https://{region}-{project}.cloudfunctions.net/"
            functions_urls.append(function_url)
        
    functions_urls = list(set(functions_urls))

    return functions_urls

def generate_filepath_urls(function_urls):

    function_urls_list = []
    with open('./Modules/CloudFunctions/utils/gcpfunctionsbrute_permutations.txt', 'r') as f:
        word_list = f.readlines()
        for word in word_list:
            for url in function_urls:
                url = url + word.strip()
                function_urls_list.append(url)


    return function_urls_list

def read_wordlist(filename):
    try:
        file = open(filename, 'r')
        lines = file.read().splitlines()
        file.close()
        return lines
    except FileNotFoundError:
        print('Error: File not found')
        exit(1)
    except PermissionError:
        print('Error: Permission denied')
        exit(1)

# Entrypoint
def run_module(user_args, session, first_run = False, last_run = False):
    
    # Set up static variables
    project_id = session.project_id

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Unauthenticated Brute Force Function URLs", allow_abbrev=False)
    
    # Debug/non-module specific
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")

    parser.add_argument('--region', required=False, default=None, help='The path to a wordlist file')
    # project ids set one level higher

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--check', required=False, action="append", help='Check a single bucket name instead of bruteforcing names based on a keyword. May be repeated to check multiple buckets.')
    group.add_argument('--check-list', required=False, default=None, help='Check a list of buckets in the given file, one per line.')
    group.add_argument('-w', '--wordlist', required=False, default=None, help='The path to a wordlist file')
    parser.add_argument('-s', '--subprocesses', required=False, default=5, type=int, help='The amount of subprocesses to delegate work to for enumeration. Default: 5. This is essentially how many threads you want to run the script with, but it is using subprocesses instead of threads.')
    
    args = parser.parse_args(user_args)
    
    # Only immplementing unauthetnicated right now
    client = None

    # Set debug flag
    debug = args.debug

    subprocesses = []
    
    function_urls = generate_function_permutations(project_id, region = args.region)

    function_filepaths = generate_filepath_urls(function_urls)

    function_urls = function_urls + function_filepaths
    
    print('\nGenerated {} function permutations.\n'.format(len(function_urls)))

    start_time = time.time()

    for i in range(0, args.subprocesses):
        start = int(len(function_urls) / args.subprocesses * i)
        end = int(len(function_urls) / args.subprocesses * (i+1))
        permutation_list = function_urls[start:end]
        subproc = Worker(client,permutation_list,debug = args.debug)
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
            print('\nScanned {} potential functions in {} day(s), {} hour(s), {} minute(s), and {} second(s).'.format(len(function_urls), d.day-1, d.hour, d.minute, d.second))
        elif d.hour > 0:
            print('\nScanned {} potential functions in {} hour(s), {} minute(s), and {} second(s).'.format(len(function_urls), d.hour, d.minute, d.second))
        elif d.minute > 0:
            print('\nScanned {} potential functions in {} minute(s) and {} second(s).'.format(len(function_urls), d.minute, d.second))
        else:
            print('\nScanned {} potential functions in {} second(s).'.format(len(function_urls), d.second))

    print('\nGracefully exiting!')


class Worker(multiprocessing.Process):
    def __init__(self, client, permutation_list, debug=False):
        multiprocessing.Process.__init__(self)
        self.client = client
        self.permutation_list = permutation_list
        self.debug = debug
    
    # dont know why this does not print in place like bucketbrute, ?
    def update_status_bar(self,current_string):
        print(f"Checking: {current_string}", end='\r')
        
        # Simulate some processing time

    def run(self):
        try:
            for function_url in self.permutation_list:

                self.update_status_bar(function_url)
                check_anonymous_external(function_url = function_url, printout = True, debug=self.debug)

        except KeyboardInterrupt:
            return