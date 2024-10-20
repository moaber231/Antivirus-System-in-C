# Antivirus System in C

## Overview
This project implements a ransomware protection software suite, as part of the HY-457 course (Introduction to Information Security Systems). The assignment focused on detecting malware based on Indicators of Compromise (IoCs), detecting harmful network traffic, securing valuable files, and protecting them from unauthorized access using secret sharing. I completed all tasks in the assignment and received a perfect score (10/10).

## Features
The project is divided into four main tasks:
1. **Scanning for Infected Files**: 
   - Detects infected files based on known malware indicators, such as file signatures, hash values (MD5, SHA256), and Bitcoin wallet addresses.
   - Scans directories recursively, computes file hashes, and checks for specific signatures.
   
2. **Detecting Potential Harmful Network Traffic**: 
   - Scans files for malicious domains using regular expressions and checks against Cloudflare's Malware Filter API.
   - Detects potential harmful interactions by scanning domain names found within files.
   
3. **Securing Valuable Files**: 
   - Monitors a secure directory for filesystem events in real-time and detects ransomware-like behaviors (file encryption, deletion).
   - Utilizes the inotify API to track events like file creation, deletion, and modification.
   
4. **Protecting from Unauthorized Access**: 
   - Implements Shamir's Secret Sharing scheme to split the decryption key among board members.
   - Requires a threshold of 3 members to reconstruct the key and decrypt files in the secure directory.

## How to Run
This project uses a **Makefile** for building and running the different modules.

### Build the Project
To build the project, run:
```bash
make
```
Run the Antivirus Scanner
To scan for infected files:

```bash
./antivirus scan <directory>
```
Run the Network Traffic Scanner
To check files for harmful network traffic:

```bash
./antivirus inspect <directory>
```
Monitor the Secure Enclave
To monitor a directory for ransomware behavior:

```bash
./antivirus monitor <directory>
```
Shamir's Secret Sharing
To split the decryption key into shares:

```bash
./antivirus slice <key>
```
To reconstruct the key from at least 3 shares:

```bash
./antivirus unlock <share1> <share2> <share3>
```
YARA Rule (Bonus Task)
To assist other cybersecurity engineers, I have written a YARA rule that describes the KozaliBear attack based on the indicators of compromise identified in the assignment.
yara
rule KozaliBear_Ransomware
{
    meta:
        description = "Detects files infected by KozaliBear ransomware"
    
    strings:
        $md5_hash = "85578cd4404c6d586cd0ae1b36c98aca"
        $sha256_hash = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849"
        $bitcoin_address = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
        $virus_signature = { 98 1d 00 00 ec 33 ff ff ?? 06 00 00 00 46 0e 10 }

    condition:
        $md5_hash or $sha256_hash or $bitcoin_address or $virus_signature
}
Project Structure
antivirus.c: Main codebase for the antivirus scanner, file monitoring, and network traffic detection.
secret_sharing.c: Implements Shamir's Secret Sharing for key management.
Makefile: Contains build rules for the project.
README.md: This file.
References
OpenSSL Library: https://www.openssl.org/docs/manmaster/
Cloudflare API for Malware Detection: https://blog.cloudflare.com/introducing-1-1-1-1-for-families
Inotify API: https://man7.org/linux/man-pages/man7/inotify.7.html
Shamir's Secret Sharing: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
YARA Rules Documentation: https://yara.readthedocs.io/en/stable/
Conclusion
This project was a great learning experience in C programming, file systems, ransomware detection, and secret sharing techniques. All the tasks were successfully implemented and tested, meeting the requirements of the assignment.

markdown

### Key Sections:
1. **Overview**: Brief description of the project and mention of your perfect score.
2. **Features**: Explanation of the four main tasks.
3. **How to Run**: Instructions on building and running each part of the project.
4. **YARA Rule**: Includes the YARA rule for detecting KozaliBear ransomware.
5. **Project Structure**: Explains the main files in the project.
6. **References**: Links to any external libraries or APIs used in the project.

This `README.md` should provide a comprehensive guide for anyone who wants to understand or run
