# Video Security Application
## By Erin Mcnulty and Emily Brown
## procedure sheet: https://docs.google.com/document/d/1P6NctRW5KSA53ahyM5wbFz-QUuS__rqUVFzkzWRZ7ME/edit?tab=t.0

## Overview

This application provides encryption and decryption functionality for video files, securing sensitive content with AES-GCM encryption. The tool uses a provided AES key and IV to encrypt and decrypt video files (.mp4). It also includes a detailed logging system to help troubleshoot the process and ensures the integrity and security of encrypted content.

## Features

- **AES-GCM Encryption**: Strong encryption using the AES-GCM cipher for securing video files.
  
- **Decryption Support**: Decrypt video files with the provided AES key and IV.
  
- **File Management**: Handles encrypted files with `.enc` extension and restores the original video file on decryption.

## How to Use

### Root User Initialization

- **The current root user**: The current root user is `eb_yes2025yay5` with a password of `test`.
  
    - To use this, you will need to initialize the TOTP key:
      ```
      qs6zvaotnxmsjth5l2getqqgkhvvxjpsxxvmcjse6pfruatwqfbg3leymqcdmnqd6kq5sgwwjbvmsjf5ypxllr3znjdzicsclq2qtma
      ```
      Utilize [this link](https://freeotp.github.io/qrcode.html) with SHA1 and timeout mode selected to generate your TOTP key taking all other values as default. 

- **creating a new root user**: 

The creation of the root (superuser) account is a highly manual development process that must be completed during server initialization. This process is essential for preparing the server for secure production deployment.

## Steps to Create the Root User

#### Step 1: Override Admin Verification
To override the admin verification, choose a user to enhance with admin privileges. If the current admin has been corrupted, the developer will need to modify the server connection handler as follows:

- Go to `DRMSystem.java` and override lines 128 through 132.
- These lines enforce the superuser requirement for the database to run.

Example of the lines to modify:
```java
String adminFilePath = config.getAdminFile();  // Assuming admin.json is in the config directory
if (!AdminVerifier.verifyAdminFile(adminFilePath)) {
    System.err.println("SECURITY ERROR: admin.json failed verification! Server shutting down.");
    System.exit(1); // Exit immediately with error code 1 (nonzero means failure)
}
```

**Note:** These lines prevent the server from running without a verified admin.

#### Step 2: Choose a User to Promote

After overriding the admin verification, choose a user to promote to admin.

1. Open `user.json` and copy the user information (except for the `aesIV` and the `encryptedAESKey`).
2. This user will be promoted to admin after the following steps are completed.

#### Step 3: Generate AES Key and IV

- The admin will need to generate the AES Key and IV for the newly created root user.

- Use the AESKeyGen utility, which is located in the root_user folder for development purposes.

- Place the generated AES Key and IV in the corresponding fields in the AdminEnhancement.java.
#### Step 4: Create admin.json
**Once the root user project has been compiled using the provided build.xml (with Ant), you can generate the admin.json file automatically.**

**To generate the admin.json file:**

- Navigate to the project directory.

- Run the following command
```bash
java -jar ./dist/root_user.jar
```
**Upon successful execution, the utility will generate an admin.json file in the following format:**
```json
{
  "username": "<copied username>",
  "password": "<copied password hash>",
  "publicKey": "<copied public key>",
  "encryptedAESKey": "<generated AES key>",
  "aesIV": "<generated IV>"
}
```
## Starting the server
**to start the server run the following bash command**
```bash
java -jar .\dist\drm.jar    
```
## Inserting a video into the database

To insert a new video into the server, the admin client must be executed with the appropriate command-line arguments like as follows.
```bash
java -jar ./dist/admin_client.jar -i -u <user> -h <host> -p <portnum> -v <filepath>
```
**you will be prompted to authenticate the admin utilizing the otp and password** 

## Creating a New User Account

To create a new user account in the system, run the following command:

```bash
java -jar ./dist/client.jar --create --user <user> --host <host> --port <portnum>
```
**The admin client will prompt for your password and a TOTP code (one-time password generated from a soft token app) after starting the user creation process.**
- use the 32 bit secret to create the otp puting it into the following application
 Utilize [this link](https://freeotp.github.io/qrcode.html) with SHA1 and timeout mode selected to generate your TOTP key taking all other values as default. 

## logging into the server
To login to the server run the following command:
```bash
  java -jar ./dist/client.jar --client --login --user <user> --host <host> --port <portnum>");
  ```
**The admin client will prompt for your password and a TOTP code (one-time password generated from a soft token app)**
Once authenticated you will see a user menu will have the following options

#### Menu Options:

- **[1] Search for Videos**  
  Allows the user to search the video library.  
  - The system will prompt the user to enter search criteria (such as video name, category, or age rating).
  - Matching videos will be listed in the console for review.

- **[2] Download a Video**  
  Enables the user to download a specific encrypted video.
  - The user will be asked to input the name of the video they wish to download.
  - Upon successful selection, the server will transfer the encrypted `.enc` file over the TLS-secured connection.
  - The client will automatically decrypt the file using the provided AES key and IV, restoring the original `.mp4` video locally.

- **[3] Exit**  
  Ends the client session gracefully.
  - Displays a goodbye message including the username.
  - Properly closes the secure TLS connection with the server.

---

> **Note:**  
> - All actions (searches, downloads) are performed over a secure TLS channel.  
> - The client must have a valid TOTP (one-time password) active session to interact with the server.
