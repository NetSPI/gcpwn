# Intro & Installation

## Hello World
gcpwn was a tool built by [myself](https://www.linkedin.com/in/webbinroot/) while trying to learn GCP and leverages the newer [GRPC client libraries](https://cloud.google.com/python/docs/reference) created by google. It consists of numerous enumeration modules I wrote plus exploit modules leveraging research done by others in the space (ex. Rhino Security) along with some existing known standalone tools like GCPBucketBrute in an effort to make the tool a one-stop-shop for GCP testing. While other exploit scripts are generally one time use, **GCPwn stores both data and permissions as you are running through modules** organizing the data for you, and re-using it to make your life easier in terms of pentesting/tracking permissions.

## Who is this for?

This tool is mainly for pentesters, those just learning GCP security, and security researchers in general.

* For pentesters, as illustrated above the tool automates a lot of scripts you would normally run and stores data to make exploit modules trivial to execute.
* For those just learning GCP security, the tool is setup in such a way that it should be easy to add your own module via a Pull request as you dive into the individual service.
* For security researchers, the tool allows you to run through a large number of GCP API calls and I document how to proxy the tool in the background through a local tool like Burp Suite. So running `enum_all` with burp suite logging all the requests will give you visibility into all the different API endpoints across all the different python libraries with one command. That's the hope at least, I got it partially working with env variables, if someone can finish cracking the code :)

## Installation Support

I tested GCPwn with the following installation setups. While its python which should theoretically work everywhere, I can't GURANTEE there are no bugs on windows/etc although happy to fix any that arise:

**Supported OS**: Kali Linux 6.6.9

**Python Version**: Python3 3.11.8

## Installation

Ideally the tool will be in pip at some point. For now, it requires a git clone and a setup script. Once you start the tool it will ask you to create a workspace (a purely logical attempt at a container, you can pass in whatever name you want) and you should be good to go. setup.sh just installs gcloud at the command line and pip install the requirements.txt if you wanted to do those separately.
```
# Setup a virtual environment
python3 -m venv ./myenv
source myenv/bin/activate

# Clone the tool locally
git clone https://github.com/NetSPI/gcpwn.git

# Run setup.sh; This will install gcloud CLI tool and pip3 install -r requirements if you want to do those separately
chmod +x setup.sh; ./setup.sh

# Launch the tool after all items installed & create first workspace
python3 main.py
[*] No workspaces were detected.
New workspace name: my_workspace
[*] Workspace 'my_workspace' created.

Welcome to your workspace! Type 'help' or '?' to see available commands.

[*] Listing existing credentials...

Submit the name or index of an existing credential from above, or add NEW credentials via Application Default 
Credentails (adc - google.auth.default()), a file pointing to adc credentials, a standalone OAuth2 Token, 
or Service credentials. See wiki for details on each. To proceed with no credentials just hit ENTER and submit 
an empty string. 
 [1] *adc      <credential_name> [tokeninfo]                    (ex. adc mydefaultcreds [tokeninfo]) 
 [2] *adc-file <credential_name> <filepath> [tokeninfo]         (ex. adc-file mydefaultcreds /tmp/name2.json)
 [3] *oauth2   <credential_name> <token_value> [tokeninfo]      (ex. oauth2 mydefaultcreds ya[TRUNCATED]i3jJK)  
 [4] service   <credential_name> <filepath_to_service_creds>    (ex. service mydefaultcreds /tmp/name2.json)

*To get scope and/or email info for Oauth2 tokens (options 1-3) include a third argument of 
"tokeninfo" to send the tokens to Google's official oauth2 endpoint to get back scope. 
tokeninfo will set the credential name for oauth2, otherwise credential name will be used.
Advised for best results. See https://cloud.google.com/docs/authentication/token-types#access-contents.
Using tokeninfo will add scope/email to your references if not auto-picked up.

Input:  
```

## TLDR;
Modules are listed below:

![image](https://github.com/NetSPI/gcpwn/assets/74038921/5c1cf902-ea03-4c50-87e6-60dbbf3c6952)

If you don't want to read through the wiki or need to run a module real quick, here are some common examples

**Enumerate Everything (Choose One that Best Fits)**
```
# Quickest: Run all enumeration modules + testIAM Permissions
modules run enum_all --iam
# Longer: Run all enumeration modules + testIAM Permissions including ~9000 for projects/folder/org
modules run enum_all --iam --all-permissions
# Longer + Downloads: Run all enumeration modules + testIAM Permissions including ~9000 for projects/folder/org + download everyting
modules run enum_all --iam --all-permissions --download
```
**Take all IAM Policy Bindings from enum_all or other modules above and return a summary/vuln analysis**
```
# Review Permissions User Has Thus Far
creds info
# Return Policy Summary from IAM Bindings if Applicable
modules run process_iam_bindings [--txt] [--csv]
# Analyze IAM Bindings + Other Items (like allUsers) if Applicable
modules run analyze_vulns [--txt] [--csv]
```

## Now What?

Open issues for any requests/bugs that might come up. In meantime, the [wiki](https://github.com/NetSPI/gcpwn/wiki) covers much more in depth different mechanisms.

Review the next few pages about loading in credentials and launching modules. 
1. Getting Started + Authentication (or no Authentication if that's your route): Load in user and/or service credentials to get creds setup
2. Calling Modules: See basics of how to call modules (spoiler its pretty easy)
3. Module Definitions: See some more details about what each module does/common trends
4. Module Creation: See how to make your own module
5. Research Head Scratchers: Things I'm trying to get working that break my brain

## Who Will Approve My Pull Requests

I will be watching issues/pulls for any cool new stuff, that being said I do have a day job so give me at least 24 hours or something :)

## Open Issues for Feature Requests/Bugs
- Tool is robust when enumerating buckets while knowing the project_id, but missing ability to just check unauthenticated bucket.
  
## Credit

Built on the shoulder of giants, credit for some code & ideas/research was inspired by:
- Rhino Security (https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)
- GCPBucketBrute (https://github.com/RhinoSecurityLabs/GCPBucketBrute)
- MUCH Google Documentation (https://cloud.google.com/python/docs/reference)
