# ČNB SDAT Signer
Very awfully (and I'm really sorry for that) forked esig/dss
demonstration project for usage as standalone signature tool
from cli. Use it on your own risk.

This fork is specifically customized for usage with 
Czech National Bank SDAT reporting system and allows signing
only by passed PKCS#12 file.

## Usage
Fork this repo and build project with maven, or download precompiled JAR file.

### JAR file CLI Parameters
    -i, --input     Input GZIP file
    -c, --pkcs      PKCS#12 certificate with key
    -p, --pwd       PKCS#12 certificate password
    -o, --output    Output signature file
~~~~
### Example
```
$ java -jar .\sdat-signer-1.0-jar-with-dependencies.jar -i .\SDAT_VYD_du3V1QJHNQT-70DMYMC0RaFccSMkl8.gzip -c .\signature.pfx -p sdat -o .\SDAT_VYD
_du3V1QJHNQT-70DMYMC0RaFccSMkl8.gzip.seal.xml
```