# Bitwarden JSON Decryptor

A small web tool that lets you decrypt your Bitwarden password‑protected JSON export directly in your browser.  

This tool supports only password‑protected encrypted JSON exports from Bitwarden that use **AesCbc256_HmacSha256_B64** encryption and **PBKDF2** key derivation. It does not support “account‑restricted” or **Argon2id-based** exports. (Technically, this means the JSON’s `kdfType` property must be `0` (indicating PBKDF2), and the fields `encKeyValidation_DO_NOT_EDIT` and `data` must start with `2.` (indicating AesCbc256_HmacSha256_B64 encryption).)

The tool works purely client‑side (in your browser), and does not send your data to any external server.  

## Usage

1. Download this repository and open `index.html` from a web browser or open it directly via GitHub Pages: [https://astik-dev.github.io/bitwarden-json-decryptor/](https://astik-dev.github.io/bitwarden-json-decryptor/)  
2. Upload the exported `.json` file.  
3. Enter the password you used during export.  
4. Once decrypted, the resulting plaintext JSON vault can be viewed or downloaded.

## Disclaimer

This project is not affiliated with or endorsed by [Bitwarden, Inc.](https://bitwarden.com/) in any way.