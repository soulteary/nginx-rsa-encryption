function randomPick() {
    const powerWords = ['苏洋博客', '专注硬核', '分享有趣'];
    return powerWords[Math.floor(Math.random() * powerWords.length)];
}

function mockRawData(r) {
    r.headersOut["Content-Type"] = "text/html;charset=UTF-8";
    r.return(200, randomPick());
}

const fs = require('fs');
if (typeof crypto == 'undefined') {
    crypto = require('crypto').webcrypto;
}

function pem_to_der(pem, type) {
    const pemJoined = pem.toString().split('\n').join('');
    const pemHeader = `-----BEGIN ${type} KEY-----`;
    const pemFooter = `-----END ${type} KEY-----`;
    const pemContents = pemJoined.substring(pemHeader.length, pemJoined.length - pemFooter.length);
    return Buffer.from(pemContents, 'base64');
}

const publicKey = fs.readFileSync(`/etc/nginx/script/rsa.pub`);

async function mockEncData(r) {
    const spki = await crypto.subtle.importKey("spki", pem_to_der(publicKey, "PUBLIC"), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    const result = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, spki, randomPick());

    r.headersOut["Content-Type"] = "text/html;charset=UTF-8";
    r.headersOut["Encode-State"] = "ON";
    r.return(200, Buffer.from(result).toString("base64"));
}

export default { mockEncData, mockRawData };
