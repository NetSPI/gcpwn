# Intro & Installation

## Hello World
gcpwn was a tool built by [myself](https://www.linkedin.com/in/webbinroot/) while trying to learn GCP and leverages the newer [GRPC client libraries](https://cloud.google.com/python/docs/reference) created by google. It consists of numerous enumeration modules I wrote plus exploit modules leveraging research done by others in the space (ex. Rhino Security) along with some existing known standalone tools like GCPBucketBrute in an effort to make the tool a one-stop-shop for GCP testing. While other exploit scripts are generally one time use, **GCPwn stores both data and permissions as you are running through modules** organizing the data for you, and re-using it to make your life easier in terms of pentesting/tracking permissions.

## Who is this for?

This tool is mainly for pentesters, those just learning GCP security, and security researchers in general.

* For pentesters, as illustrated above the tool automates a lot of scripts you would normally run and stores data to make exploit modules trivial to execute.
* For those just learning GCP security, the tool is setup in such a way that it should be easy to add your own module via a Pull request as you dive into the individual service.
* For security researchers, the tool allows you to run through a large number of GCP API calls and I document how to proxy the tool in the background through a local tool like Burp Suite. So running `enum_all` with burp suite logging all the requests will give you visibility into all the different API endpoints across all the different python libraries with one command. That's the hope at least, I got it partially working with env variables, if someone can finish cracking the code :)

## Wiki Instructions

Review the wiki at https://github.com/NetSPI/gcpwn/wiki for: 
1. Installation Instructions & Folder Setup: How to set up the tool for first-time use and default folders used
2. Authentication Management & Tokeninfo: Load in user and/or service credentials to get creds setup
3. Managing Projects & Retrieving Resource Data: How to manage Project IDs and how to retrieve enumerated data from SQLite tables.
4. Modules Guide: How to call a module + deep dive on each module
5. Module Creation: How to add your own module via pull request
5. Research Head Scratchers: Research topics/open questions

## The TLDR

If you already have the tool installed and want quick commands to run, then you can usually run the `enum_all` module followed by `creds info` to view newly enumerated permissions. The `process_iam_bindings` module will then give you a TXT/CSV summary of policy bindings if they can be enumerated, and `analyze_vulns` will try to flag bad roles/permissions. See the common flags below.

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

## Who Will Approve My Pull Requests

I will be watching issues/pulls for any cool new stuff, that being said I do have a day job so give me at least 24 hours or something :)

## Credit

Built on the shoulder of giants, credit for some code & ideas/research was inspired by:
- Rhino Security (https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)
- GCPBucketBrute (https://github.com/RhinoSecurityLabs/GCPBucketBrute)
- MUCH Google Documentation (https://cloud.google.com/python/docs/reference)
