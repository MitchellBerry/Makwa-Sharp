<p align="center">
  <br><br>
  <img src="https://raw.githubusercontent.com/MitchellBerry/Makwa-Sharp/master/Docs/makwa-logo.png">
</p>

# Makwa-Sharp

[![NuGet](https://img.shields.io/nuget/v/Makwa.svg)](https://www.nuget.org/packages/Makwa/1.0.0) [![Hex.pm](https://img.shields.io/hexpm/l/plug.svg)](https://github.com/MitchellBerry/Makwa-Sharp/blob/master/License.md)

A pure C# Makwa implementation with no dependencies. 

Makwa was a runner up in the Password Hashing Competition, uniquely has a delegation function which allows hashing to be offloaded onto a third party server without revealing the password.

## Installation

#### Nuget
    Install-Package Makwa

#### .NET

    dotnet add package Makwa

#### Git

    git clone https://github.com/MitchellBerry/Makwa-Sharp.git

## Usage

#### Basic

```csharp
using Makwa;

Hasher makwa = Hasher.Create();
String password = "hunter2";
String hash = makwa.HashPassword(password);
// hash: SdVTLgfGKck_b211_TG3Uljw178dpAPtw1qILPA_JMm2w54jILdKKQMp
```
#### Verify Password

```csharp
String hash = "SdVTLgfGKck_b211_TG3Uljw178dpAPtw1qILPA_JMm2w54jILdKKQMp"
bool correct_password = makwa.VerifyPassword(password, hash)
```

#### Custom Parameters

```csharp
makwa.Prehashing = false;
makwa.Posthashing = 16;
makwa.Workfactor = 384;
makwa.Hashfunction = new HMACSHA512();
String hash = makwa.HashPassword(password);
// hash: SdVTLgfGKck_s307_Qh0ZKgAwQr+ieFauHFm4Vg_3B/H3xbYZZa2Ua2yfK55mA
```

#### Key Derivation Function Only
```csharp
byte[] input_bytes = new byte[87]; //[0x00, 0x00, 0x00 ...]
int output_length = 173;
byte[] kdf_output = makwa.KDF(input_bytes, output_length);
```

#### Hash Digest Bytes

```csharp
byte[] salt = new byte[16]; //Use an appropriately random input, 16 bytes long
byte[] password_bytes = Encoding.UTF8.GetBytes(password);
byte[] digest_bytes = makwa.Digest(password_bytes, salt);
// digest byte array, length is determined by Posthashing value
```

## Parameters

|     Name     	|  Type  	|                                                                                                                                                                                           Effect                                                                                                                                                                                           	|   Default  	|
|:------------:	|:------:	|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:	|:----------:	|
|  Prehashing  	|  bool  	|                                                                                                                                               Hashes the input prior to the running the main Makwa algorithm. Allows an unlimited input size.                                                                                                                                              	|    True    	|
|  Posthashing 	| ushort 	|                                                                       Hashes the result down to the specified size, the default value of 12 results in a 12 byte digest. A value of 0 applies no post-hashing and the digest will be the full size, values between 1 and 9 are not valid and will raise an exception.                                                                      	|     12     	|
|  Workfactor  	|  uint  	|  The number of rounds performed, a higher number will increase hashing time. Work factors are restricted to values w = x * 2<sup>y</sup>, where x = 2 or 3 and y ≥ 0, other values will raise an error suggesting the closest valid value. (See notes below)	|    4096    	|
| Hashfunction 	|  HMAC  	|                                                                                                                                                              A HMAC object, only HMACSHA256 and HMACSHA512 are valid options.                                                                                                                                                              	| HMACSHA256 	|



## Testing

Testing is setup for Visual Studio, playlists are provided to reduce testing time rather than going through the full set, TestWorkFactor384 will significantly reduce time taken.
Running the full test suite should take ~30 mins on an average cpu. The kats.txt file consists of 400 KDF and 2000 Makwa known answer tests.

## Notes

* This implementation enforces specific work factors of the form w = ζ · 2ᵟ, where ζ = 2 or 3, and δ ≥ 0. Some valid work factors: 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384

* The final hash string doesn't differentiate between SHA-256 and SHA-512. If verifying from an unknown source test both algorithms.

* A unique 2048-bit modulus is generated on first use and stored in the libraries folder as a binary file named modulus, generating your own is possible through either OpenSSL or the MakwaPrivateKey class as is testing for primality and correct type. Modulus must be a Blum integer which is the product of 2 primes p & q of the type: prime ≡ 3 (mod 4).

* A standalone .dll is available [here](https://github.com/MitchellBerry/Makwa-Sharp/releases/latest)

* The use of Pre and Post hashing affects certain features (delegation and fast-path are unaffected):

<p align="center">
  <br><br>
  <img src="https://raw.githubusercontent.com/MitchellBerry/Makwa-Sharp/master/Docs/prepostmakwa.png">
</p>


