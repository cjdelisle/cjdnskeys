# cjdnskeys - tools for working with cjdns keys

```javascript
const Cjdnskeys = require('cjdnskeys');

Cjdnskeys.keyPair() /*
{ privateKey: '378813dfecc62185ffab4d00030b55f50b54e515bfcea8b41f2bd1c2511bae03',
  publicKey: 'qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k',
  ip6: 'fcf5:c1ec:be67:9ad5:1f6c:f31b:5d74:37b0' } */

Cjdnskeys.privateToPublic("378813dfecc62185ffab4d00030b55f50b54e515bfcea8b41f2bd1c2511bae03")
// "qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k"

Cjdnskeys.publicToIp6("qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k")
// "fcf5:c1ec:be67:9ad5:1f6c:f31b:5d74:37b0"

Cjdnskeys.validate("378813dfecc62185ffab4d00030b55f50b54e515bfcea8b41f2bd1c2511bae03") // true
Cjdnskeys.validate("qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k") // true
Cjdnskeys.validate("fcf5:c1ec:be67:9ad5:1f6c:f31b:5d74:37b0") // true
```

## Conversion Functions

```javascript
const Cjdnskeys = require('cjdnskeys');

Cjdnskeys.keyStringToBytes("qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k")
// <Buffer d6 45 c8 00 ce 6d c7 74 07 14 08 13 f7 d0 75 58 2a d7 c5 2d dd f5 df a3 9b 65 b3 ...>

Cjdnskeys.keyBytesToString(new Buffer('1kXIAM5tx3QHFAgT99B1WCrXxS3d9d+jm2WzbjlFHWs=', 'base64'))
// "qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k"

Cjdnskeys.ip6StringToBytes("fcf5:c1ec:be67:9ad5:1f6c:f31b:5d74:37b0")
// <Buffer fc f5 c1 ec be 67 9a d5 1f 6c f3 1b 5d 74 37 b0>

Cjdnskeys.ip6BytesToString(new Buffer("fcf5c1ecbe679ad51f6cf31b5d7437b0", "hex"))
// "fcf5:c1ec:be67:9ad5:1f6c:f31b:5d74:37b0"
```
