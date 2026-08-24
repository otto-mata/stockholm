WannaCry uses a multi-tier hybrid encryption scheme combining symmetric (AES-128-CBC) and asymmetric (RSA-2048) cryptography.
## The Key Hierarchy
WannaCry relies on a chain of three distinct sets of keys to lock files:

   1. Master RSA Key Pair (Attacker Keys):
   * The Private Key remains with the attackers.
      * The Public Key is hardcoded directly inside the WannaCry malware executable.
   2. Local RSA Key Pair (Victim Keys):
   * Generated dynamically on the victim’s computer when the malware executes.
      * The Local Private Key is immediately encrypted using the attacker's hardcoded Master Public Key and saved to disk as 00000000.eky.
      * The Local Public Key is saved unencrypted on disk as 00000000.pky.
   3. Per-File AES Keys:
   * A unique 128-bit AES key is randomly generated for every single file that gets encrypted.
   
------------------------------
## Step-by-Step Encryption Process
When the malware targets a specific file, it executes the following technical workflow:

```
[Original File] ----> ( AES-128-CBC Encryption via Random Key ) ----> [Encrypted File Payload]
                                       ^
                                       | (Encrypted by)
                         [Local RSA-2048 Public Key] 
                                       |
                                       v
                        [Encrypted AES Key in Header]
```

   1. Generate AES Key: WannaCry uses the Windows CryptoAPI to generate a random 128-bit AES key for the specific target file.
   2. Encrypt File Content: The file content is encrypted using AES-128 in CBC mode. As noted previously, the Initialization Vector (IV) is set to all zeros.
   3. Secure the AES Key: The unique AES key is encrypted using the victim's Local RSA Public Key (00000000.pky).
   4. Construct the .WNCRY File: The malware overwrites or replaces the original file with a new file containing a custom header followed by the encrypted content.

The custom header is exactly 256 bytes long and contains:

* 8 bytes: Magic string (WANACRY!)
* 4 bytes: Unused/padding marker
* 4 bytes: Length of the encrypted AES key component (usually 0x0100 or 256 bytes total for the RSA block)
* 240 bytes: The RSA-encrypted payload (which holds the file's unique AES key and metadata)

------------------------------
## Step-by-Step Decryption Process (How Ransom is Paid)
To unlock the files, the inverse operation must occur, which requires the attacker's cooperation:

   1. Submit Local Key: The victim sends the 00000000.eky file (the encrypted Local Private Key) to the attackers after paying the ransom.
   2. Attacker Decryption: The attackers use their Master RSA Private Key to decrypt 00000000.eky. This yields the victim's raw Local RSA Private Key.
   3. Return Private Key: The attackers send this decrypted Local RSA Private Key back to the victim's local decryptor software.
   4. Decrypt AES Keys: The local decryptor uses the Local RSA Private Key to read the 256-byte header of every .WNCRY file and extract each file's unique AES key.
   5. Decrypt Files: The unique AES keys decrypt the actual file contents back into their original format.

------------------------------
If you want to dive deeper, let me know if you would like to explore:

* The Windows CryptoAPI functions (CryptGenKey, CryptEncrypt) used in the source code
* The WannaCry flaw that allowed temporary recovery tools (like WanaKiwi) to bypass this scheme
* A breakdown of the file system operations during encryption (e.g., memory mapping vs. temporary files)


