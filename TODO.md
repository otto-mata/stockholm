# Stockholm

## Requirements

### Must

- Handle options '-h[elp]', '-v[ersion]', '-r[everse] <key>' and '-s[ilent]'
- Work only in ~/infection
- Act only on the extensions listed in INFECTION.ini
- Encrypt infected file with a known and secure algorithm (research needed)
- Rename encrypted file, appending ".ft" (unless the file already ends with this extension)
- Have an encryption key of at least 16 characters
- Be able to successfully decrypt the infected files
