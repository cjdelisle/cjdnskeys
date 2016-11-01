/* vim: set expandtab ts=4 sw=4: */
/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
'use strict';
const Crypto = require('crypto');
const Nacl = require('tweetnacl');

const NUM_FOR_ASCII = [
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,99,99,99,99,99,99,
    99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,
    21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,
    99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,
    21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,
];
const B32_CHARS = "0123456789bcdfghjklmnpqrstuvwxyz".split('');
const PRIV_REGEX = /^[0-9a-fA-F]{64}$/;
const PUB_REGEX = /[a-z0-9]{52}\.k/;
const IP6_REGEX = /^fc[0-9a-f]{2}:[0-9a-f:]+$/;

// see util/Base32.h
const Base32_decode = (input) => {
    const output = [];
    let outputIndex = 0;
    let inputIndex = 0;
    let nextByte = 0;
    let bits = 0;

    while (inputIndex < input.length) {
        const o = input.charCodeAt(inputIndex);
        if (o & 0x80) { throw new Error(); }
        const b = NUM_FOR_ASCII[o];
        inputIndex++;
        if (b > 31) { throw new Error("bad character " + input[inputIndex] + " in " + input); }

        nextByte |= (b << bits);
        bits += 5;

        if (bits >= 8) {
            output[outputIndex] = nextByte & 0xff;
            outputIndex++;
            bits -= 8;
            nextByte >>= 8;
        }
    }

    if (bits >= 5 || nextByte) {
        throw new Error("bits is " + bits + " and nextByte is " + nextByte);
    }

    return new Buffer(output);
};

const Base32_encode = (input) => {
    let outIndex = 0;
    let inIndex = 0;
    let work = 0;
    let bits = 0;
    const output = [];

    while (inIndex < input.length) {
        work |= (input[inIndex++] << bits);
        bits += 8;

        while (bits >= 5) {
            output[outIndex++] = B32_CHARS[work & 31];
            bits -= 5;
            work >>= 5;
        }
    }

    if (bits) {
        output[outIndex++] = B32_CHARS[work & 31];
        bits -= 5;
        work >>= 5;
    }
    return output.join('');
};

const keyBytesToString = module.exports.keyBytesToString = (bytes) => {
    if (bytes.length !== 32) { throw new Error("unexpected length [" + bytes.length + "]"); }
    return Base32_encode(bytes) + '.k';
};

const keyStringToBytes = module.exports.keyStringToBytes = (pubKey) => {
    if (!PUB_REGEX.test(pubKey)) { throw new Error("key does not look valid"); }
    return Base32_decode(pubKey.substring(0, pubKey.length-2));
};

const ip6BytesToString = module.exports.ip6BytesToString = (ip6) => {
    if (ip6.length !== 16) { throw new Error("bad length"); }
    if (ip6[0] !== 0xfc) { throw new Error("does not begin with fc"); }
    return ip6.toString('hex').replace(/[a-z0-f]{4}/g, (x) => (x + ':')).slice(0,-1);
};

const ip6StringToBytes = module.exports.ip6StringToBytes = (ip6Str) => {
    if (ip6Str.length !== 39) { throw new Error("bad length"); }
    if (!IP6_REGEX.test(ip6Str)) { throw new Error("ip addr does not begin with fc"); }
    const hex = ip6Str.split(':').map((x) => ( new Array(5 - x.length).join('0') + x ) ).join('');
    return new Buffer(hex, 'hex');
};

const publicToIp6 = module.exports.publicToIp6 = (pubKey) => {
    const keyBytes = keyStringToBytes(pubKey);
    const hash1Buff = new Buffer(Crypto.createHash('sha512').update(keyBytes).digest('hex'), 'hex');
    const hash2 = Crypto.createHash('sha512').update(hash1Buff).digest('hex');
    const first16 = hash2.substring(0,32);
    const out = [];
    for (let i = 0; i < 8; i++) {
        out.push(first16.substring(i*4, i*4+4));
    }
    return out.join(':');
};

const privateToPublic = module.exports.privateToPublic = (privateKey) => {
    if (typeof(privateKey) !== 'string' || !PRIV_REGEX.test(privateKey)) {
        throw new Error("key must by 64 char long hex string");
    }
    const kp = Nacl.box.keyPair.fromSecretKey(new Buffer(privateKey, 'hex'));
    return keyBytesToString(kp.publicKey);
};

const keyPair = module.exports.keyPair = () => {
    for (;;) {
        let privateKey = new Buffer(Nacl.randomBytes(32)).toString('hex');
        console.log(privateKey);
        let publicKey = privateToPublic(privateKey);
        let ip6 = publicToIp6(publicKey);
        if (IP6_REGEX.test(ip6)) {
            return { privateKey: privateKey, publicKey: publicKey, ip6: ip6 };
        }
    }
};

const validate = module.exports.validate = (x) => {
    if (PRIV_REGEX.test(x)) { return validate(privateToPublic(x)); }
    if (PUB_REGEX.test(x)) { return validate(publicToIp6(x)); }
    return IP6_REGEX.test(x);
};
