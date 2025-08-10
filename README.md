# Kryptologie Lab - Cryptographic Algorithms Implementation

This project contains implementations of various cryptographic algorithms in Java, organized by cryptographic categories.

## Prerequisites

- Java 21 or higher
- Maven 3.6+ (see installation instructions below)
- Bouncy Castle library (automatically managed by Maven)

### Installing Maven on Windows

If you get the error "mvn is not recognized", you need to install Maven:

**Option 1: Using Chocolatey (Recommended)**
```powershell
# Install Chocolatey first (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Maven
choco install maven
```

**Option 2: Manual Installation**
1. Download Maven from https://maven.apache.org/download.cgi
2. Extract to `C:\Program Files\Apache\maven`
3. Add `C:\Program Files\Apache\maven\bin` to your system PATH
4. Restart PowerShell/Command Prompt

**Option 3: Using your IDE**
- If using IntelliJ IDEA, Maven is bundled - use the IDE's Maven integration
- Right-click on `pom.xml` → "Add as Maven Project"

## Building the Project

### Using Maven (Recommended)

To build the entire project:

```bash
mvn clean compile
```

To create a JAR file:

```bash
mvn clean package
```

### Alternative: Direct Java Compilation (if Maven is not available)

If Maven is not installed, you can compile and run directly using Java:

```powershell
# Navigate to project root
cd "c:\Users\khale\IdeaProjects\kryptologie_Lab_new"

# Create output directory
mkdir -Force target\classes

# Download Bouncy Castle JAR manually (if needed)
# Download bcprov-jdk15on-1.70.jar from https://www.bouncycastle.org/latest_releases.html
# Place it in a 'lib' folder

# Compile all Java files
javac -cp "lib\*" -d target\classes src\main\java\org\example\**\*.java

# Copy resource files
Copy-Item -Recurse src\main\java\org\example\*\*.txt target\classes\org\example\ -Force
```

## Project Structure

```
src/main/java/org/example/
├── Main.java                     # Main entry point
├── addativeChiffere/             # Classical ciphers (Caesar, Vigenère)
├── aes/                          # AES encryption implementation
├── diffie/                       # Diffie-Hellman key exchange
├── dsa/                          # Digital Signature Algorithm
├── lineareAnalysis/              # Linear cryptanalysis tools
├── rsa/                          # RSA encryption
└── sha/                          # SHA hash function
```

## Quick Start (Without Maven)

If you want to test immediately without installing Maven:

1. **Open the project in your IDE** (IntelliJ IDEA, Eclipse, VS Code with Java extension)
2. **Make sure Java 21+ is configured**
3. **Run any main class directly from your IDE:**
   - Navigate to any class with a `main` method
   - Right-click → "Run ClassName.main()"
   - Add arguments in the run configuration if needed

**Example: Test Caesar Cipher**
1. Open `src/main/java/org/example/addativeChiffere/Caeser.java`
2. Right-click → "Run Caeser.main()"
3. In run configuration, add arguments: `src/main/java/org/example/addativeChiffere/Klartext_1.txt 7 output.txt`

---

## Running Individual Components

### Execution Methods

**Method 1: Using Maven (Recommended)**
```bash
mvn exec:java -Dexec.mainClass="org.example.ClassName" -Dexec.args="arg1 arg2"
```


**Method 4: Using IDE**
- Right-click on the class with main method → "Run ClassName.main()"
- Configure run arguments in your IDE's run configuration

---



---

### 2. Classical Ciphers (`addativeChiffere` package)

#### Caesar Cipher (`org.example.addativeChiffere.Caeser`)

**Purpose**: Caesar cipher encryption/decryption

**Usage with Maven:**
```bash
# Encrypt/Decrypt with key
mvn exec:java -Dexec.mainClass="org.example.addativeChiffere.Caeser" -Dexec.args="src/main/java/org/example/addativeChiffere/Klartext_1.txt 7 src/main/java/org/example/addativeChiffere/output.txt"


# Brute force attack (find key)
mvn exec:java -Dexec.mainClass="org.example.addativeChiffere.Caeser" -Dexec.args="src/main/java/org/example/addativeChiffere/output.txt src/main/java/org/example/addativeChiffere/decrypted_output.txt"
```


**Arguments:**
- 3 args: `[input_file] [key] [output_file]` - Encrypt/decrypt with given key
- 2 args: `[ciphertext_file] [output_file]` - Brute force to find key

**Example files:**
- `src/main/java/org/example/addativeChiffere/Klartext_1.txt`
- `src/main/java/org/example/addativeChiffere/Kryptotext_1_Key_7.txt`

#### Vigenère Cipher (`org.example.addativeChiffere.Vigenere`)

**Purpose**: Vigenère cipher encryption/decryption

**Usage:**
```bash
# Encrypt
mvn exec:java -Dexec.mainClass="org.example.addativeChiffere.Vigenere" -Dexec.args="encrypt src/main/java/org/example/addativeChiffere/Klartext_Vig.txt TAG src/main/java/org/example/addativeChiffere/vigenere_encrypted_tag.txt"

# Decrypt (automatic key finding) using analysis
mvn exec:java -Dexec.mainClass="org.example.addativeChiffere.Vigenere" -Dexec.args="decrypt src/main/java/org/example/addativeChiffere/Kryptotext_TAG.txt src/main/java/org/example/addativeChiffere/vigenere_decrypted.txt"
```

**Commands:**
- `encrypt [input_file] [key] [output_file]` - Encrypt with given key
- `decrypt [input_file] [output_file]` - Automatically find key and decrypt

**Example files:**
- `src/main/java/org/example/addativeChiffere/Klartext_Vig.txt`
- `src/main/java/org/example/addativeChiffere/Kryptotext_TAG.txt`

---

### 3. AES Implementation (`aes` package)

#### AES Cipher (`org.example.aes.AesCipher`)

**Purpose**: AES-128 block encryption/decryption

**Usage:**
```bash
# Encrypt
mvn exec:java -Dexec.mainClass="org.example.aes.AesCipher" -Dexec.args="encrypt src/main/java/org/example/aes/Beispiel_1_Klartext.txt src/main/java/org/example/aes/SBox.txt src/main/java/org/example/aes/Beispiel_key.txt src/main/java/org/example/aes/output.txt"

# Decrypt
mvn exec:java -Dexec.mainClass="org.example.aes.AesCipher" -Dexec.args="decrypt src/main/java/org/example/aes/output.txt src/main/java/org/example/aes/SBox.txt src/main/java/org/example/aes/Beispiel_key.txt src/main/java/org/example/aes/decrypted_output.txt"
```

**Arguments:**
- `encrypt [input_file] [sbox_file] [key_file] [output_file]`
- `decrypt [input_file] [sbox_file] [key_file] [output_file]`

**Example files:**
- `src/main/java/org/example/aes/Beispiel_1_Klartext.txt` - Plaintext
- `src/main/java/org/example/aes/Beispiel_1_Kryptotext.txt` - Ciphertext
- `src/main/java/org/example/aes/Beispiel_key.txt` - Key
- `src/main/java/org/example/aes/SBox.txt` - S-Box

#### AES Block Cipher Modes (`org.example.aes.BlockCipherModes`)

**Purpose**: AES with different block cipher modes (ECB, CBC, CFB, OFB, CTR)

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.aes.BlockCipherModes" -Dexec.args="-m OFB -o encrypt -i src/main/java/org/example/aes/Beispiel_1_Klartext.txt -k src/main/java/org/example/aes/Beispiel_key.txt -out src/main/java/org/example/aes/output.txt -s src/main/java/org/example/aes/SBox.txt -b 16 -iv src/main/java/org/example/aes/IV"
```

**Required Arguments:**
- `-m [mode]` - Cipher mode: ECB, CBC, CFB, OFB, CTR
- `-o [operation]` - Operation: encrypt or decrypt
- `-i [input_file]` - Input file path
- `-k [key_file]` - Key file path
- `-out [output_file]` - Output file path

**Optional Arguments:**
- `-iv [iv_file]` - Initialization vector file (required for CBC, CFB, OFB, CTR)
- `-s [sbox_file]` - S-Box file (default: `src/main/java/org/example/aes/SBox.txt`)
- `-b [block_size]` - Block size in bytes (default: 16)

**Examples:**
```bash
# ECB mode encryption
mvn exec:java -Dexec.mainClass="org.example.aes.BlockCipherModes" -Dexec.args="-m ECB -o encrypt -i src/main/java/org/example/aes/Beispiel_1_Klartext.txt -k src/main/java/org/example/aes/Beispiel_key.txt -out encrypted.txt"

# CBC mode with IV
mvn exec:java -Dexec.mainClass="org.example.aes.BlockCipherModes" -Dexec.args="-m CBC -o encrypt -i input.txt -k key.txt -iv iv.txt -out output.txt"
```

---

### 4. RSA Implementation (`rsa` package)

#### RSA Key Generator (`org.example.rsa.RSAKeygenerator`)

**Purpose**: Generate RSA key pairs

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.rsa.RSAKeygenerator" -Dexec.args="50 src/main/java/org/example/rsa/private.key src/main/java/org/example/rsa/public.key src/main/java/org/example/rsa/primes.key"
```

**Output:** Generates `public.key` and `private.key` files

**Arguments:**
- `[input_file]` - File Path for input 
- `[output_file]` - File Path for output
- `[primes]` - file Path for primes
- `[size]` -  size in bits (e.g., 50)


#### RSA Encryption/Decryption (`org.example.rsa.RSA`)

**Purpose**: RSA encryption and decryption

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.rsa.RSA" -Dexec.args="encrypt src/main/java/org/example/rsa/ExampleText.txt src/main/java/org/example/rsa/public.key src/main/java/org/example/rsa/output.txt"
mvn exec:java -Dexec.mainClass="org.example.rsa.RSA" -Dexec.args="encrypt src/main/java/org/example/rsa/output.txt src/main/java/org/example/rsa/private.key src/main/java/org/example/rsa/decryptOutput.txt"

```

**Arguments:**
- `[input_file]` - File containing number to encrypt/decrypt
- `[key_file]` - Key file (public or private key)
- `[output_file]` - Output destination

**Example files:**
- `src/main/java/org/example/rsa/ExampleText.txt` - Input text
- `src/main/java/org/example/rsa/ExampleKey.txt` - Key file
- `src/main/java/org/example/rsa/public.key` - Public key
- `src/main/java/org/example/rsa/private.key` - Private key

---

### 5. Digital Signature Algorithm (`dsa` package)

#### DSA Key Generation (`org.example.dsa.DsaKeyGen`)

````aiignore
!! dont change the argument  String pubFile = "src/main/java/org/example/dsa/" + args[0]; its already confiugred in the code
````

**Purpose**: Generate DSA key pairs

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.dsa.DsaKeyGen" -Dexec.args="pubFile.txt priFile.txt"
```

**Arguments:**
- `[public_key_file]` - Public key output filename
- `[private_key_file]` - Private key output filename

#### DSA Signing (`org.example.dsa.DsaSign`)

**Purpose**: Create digital signatures

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.dsa.DsaSign" -Dexec.args="message.txt priFile.txt signed.txt"
```

**Arguments:**
- `[message_file]` - Message to sign
- `[private_key_file]` - Private key file
- `[signature_output_file]` - Signature output file

#### DSA Verification (`org.example.dsa.DsaVerify`)

**Purpose**: Verify digital signatures

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.dsa.DsaVerify" -Dexec.args="message.txt pubFile.txt signed.txt"
```

**Arguments:**
- `[message_file]` - Original message
- `[public_key_file]` - Public key file
- `[signature_file]` - Signature file to verify


**Example workflow:**
```bash
# 1. Generate keys
mvn exec:java -Dexec.mainClass="org.example.dsa.DsaKeyGen" -Dexec.args="pubFile.txt priFile.txt"

# 2. Sign message
mvn exec:java -Dexec.mainClass="org.example.dsa.DsaSign" -Dexec.args="priFile.txt message.txt signed.txt"

# 3. Verify signature
mvn exec:java -Dexec.mainClass="org.example.dsa.DsaVerify" -Dexec.args="pubFile.txt message.txt signed.txt"
  ```

---

### 6. Diffie-Hellman Key Exchange (`diffie` package)

#### DH Parameter Generator (`org.example.diffie.DHParamGenerator`)

**Purpose**: Generate Diffie-Hellman parameters (p, g)

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.diffie.DHParamGenerator" -Dexec.args="50"
```

**Output:** Creates `dhparams.txt` with p and g values

#### DH Key Exchange (`org.example.diffie.DHExchange`)

**Purpose**: Perform Diffie-Hellman key exchange

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.diffie.DHExchange"
```

**Prerequisites:** Requires `dhparams.txt` file (created by DHParamGenerator)

**Example workflow:**
```bash
# 1. Generate parameters
mvn exec:java -Dexec.mainClass="org.example.diffie.DHParamGenerator"

# 2. Perform key exchange
mvn exec:java -Dexec.mainClass="org.example.diffie.DHExchange"
```
* First run the DHParamGenerator to create the `dhparams.txt` file, then run the DHExchange to perform the key exchange.

---

### 7. SHA Hash Function (`sha` package)

#### SHA Implementation (`org.example.sha.SHA`)

**Purpose**: SHA-1 hash function implementation

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.sha.SHA" -Dexec.args="src/main/java/org/example/sha/Input.txt src/main/java/org/example/sha/Output.txt"
```

**Arguments:**
- `[input_hex_file]` - File containing hex input
- `[output_digest_file]` - Output file for hash digest

**Example files:**
- `src/main/java/org/example/sha/Input.txt` - Hex input
- `src/main/java/org/example/sha/Output.txt` - Hash output

---

### 8. Linear Cryptanalysis (`lineareAnalysis` package)

#### Linear Approximation (`org.example.lineareAnalysis.LinApprox`)

**Purpose**: Linear cryptanalysis of SPN ciphers

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.lineareAnalysis.LinApprox" -Dexec.args="generate src/main/java/org/example/lineareAnalysis/genreatedPlainText.txt src/main/java/org/example/lineareAnalysis/ciphergenerated.txt 1000 2b7e"
# Analyze the generated plaintext-ciphertext pairs
mvn exec:java -Dexec.mainClass="org.example.lineareAnalysis.LinApprox" -Dexec.args="src/main/java/org/example/lineareAnalysis/genreatedPlainText.txt src/main/java/org/example/lineareAnalysis/ciphergenerated.txt"

mvn exec:java -Dexec.mainClass="org.example.lineareAnalysis.LinApprox" -Dexec.args="src/main/java/org/example/lineareAnalysis/genreatedPlainText.txt src/main/java/org/example/lineareAnalysis/ciphergenerated.txt src/main/java/org/example/lineareAnalysis/predictedOutput.txt"

```

**Commands:**
- `generate [plain_file] [cipher_file] [num_pairs] [key_hex]` - Generate pairs
- `[plain_file] [cipher_file]` - Analyze pairs
- `[plain_file] [cipher_file] [outputfile]` - Analyze with specfic output file name or path

#### Quality Approximation (`org.example.lineareAnalysis.GueteApporximation`)

**Purpose**: Quality assessment of linear approximations

**Usage:**
```bash
mvn exec:java -Dexec.mainClass="org.example.lineareAnalysis.GueteApporximation" -Dexec.args="src/main/java/org/example/lineareAnalysis/Sbox-Example src/main/java/org/example/lineareAnalysis/approximationExampleGueteAppr src/main/java/org/example/lineareAnalysis/quality_output.txt"
```

#### SPN Cipher (`org.example.lineareAnalysis.Spn`)

**Purpose**: SPN (Substitution-Permutation Network) cipher implementation

**Usage:**
```bash
# Encrypt using SPN
mvn exec:java -Dexec.mainClass="org.example.lineareAnalysis.Spn" -Dexec.args="src/main/java/org/example/lineareAnalysis/Beispiel_1_Klartext.txt src/main/java/org/example/lineareAnalysis/Beispiel_key.txt src/main/java/org/example/lineareAnalysis/spn_encrypted.txt encrypt"
mvn exec:java -Dexec.mainClass="org.example.lineareAnalysis.Spn" -Dexec.args="src/main/java/org/example/lineareAnalysis/spn_encrypted.txt src/main/java/org/example/lineareAnalysis/Beispiel_key.txt src/main/java/org/example/lineareAnalysis/spn_decrypted.txt decrypt"

```
**Commands:**
- `[Klartext_file] [key_file] [outputfile] encrypt` - encrypt
- `[Klartext_file] [key_file] [outputfile] dcrypt` - decrypt


---

## Common File Locations

Most input/output files are located in their respective package directories:

- **AES files**: `src/main/java/org/example/aes/`
- **Caesar/Vigenère files**: `src/main/java/org/example/addativeChiffere/`
- **RSA files**: `src/main/java/org/example/rsa/`
- **DSA files**: `src/main/java/org/example/dsa/`
- **SHA files**: `src/main/java/org/example/sha/`
- **Linear analysis files**: `src/main/java/org/example/lineareAnalysis/`

## Example Workflow

Here's a complete example using AES:

```bash
# 1. Build the project
mvn clean compile

# 2. Encrypt using AES
mvn exec:java -Dexec.mainClass="org.example.aes.AesCipher" -Dexec.args="encrypt src/main/java/org/example/aes/Beispiel_1_Klartext.txt src/main/java/org/example/aes/SBox.txt src/main/java/org/example/aes/Beispiel_key.txt encrypted_output.txt"
# 3. Decrypt the ciphertext
mvn exec:java -Dexec.mainClass="org.example.aes.AesCipher" -Dexec.args="decrypt encrypted_output.txt src/main/java/org/example/aes/SBox.txt src/main/java/org/example/aes/Beispiel_key.txt decrypted_output.txt"
```

## Notes

- All file paths should be relative to the project root or absolute paths
- Hex input files should contain space-separated hexadecimal values
- Key files format depends on the specific algorithm (see example files)
- Some tools generate their own input files (e.g., key generators)
- Error messages will guide you if arguments are missing or incorrect

## Dependencies

The project uses Maven for dependency management. The main external dependency is:

- **Bouncy Castle Provider** (v1.70) - For additional cryptographic functionality

To install dependencies:
```bash
mvn clean install
```

## Troubleshooting

### "mvn is not recognized" Error
- **Solution**: Install Maven (see Prerequisites section above) or use alternative methods
- **Quick fix**: Use your IDE's built-in Maven support or run classes directly

### "Could not find or load main class" Error
- **Solution**: Make sure you've compiled the project first
- **Check**: Verify that `target\classes` directory exists and contains compiled `.class` files

### "ClassNotFoundException" or missing dependencies
- **Solution**: Ensure Bouncy Castle JAR is in classpath
- **For direct Java execution**: Download `bcprov-jdk15on-1.70.jar` and place in `lib\` folder

### File path issues
- **Windows**: Use backslashes `\` in file paths or forward slashes `/`
- **Relative paths**: All examples assume you're in the project root directory
- **Absolute paths**: Use full Windows paths like `C:\Users\...\file.txt`

### PowerShell execution policy error
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```