
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

const rsaKeys = {
  public: fs.readFileSync(`/etc/nginx/script/rsa.pub`),
  private: fs.readFileSync(`/etc/nginx/script/rsa.key`)
}


async function encrypt(req) {
  const needBase64 = req.uri.indexOf('base64=1') > -1;
  const spki = await crypto.subtle.importKey("spki", pem_to_der(rsaKeys.public, "PUBLIC"), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const result = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, spki, req.requestText);
  if (needBase64) {
    req.return(200, Buffer.from(result).toString("base64"));
  } else {
    req.headersOut["Content-Type"] = "application/octet-stream";
    req.return(200, Buffer.from(result));
  }
}

async function decrypt(req) {
  const needBase64 = req.uri.indexOf('base64=1') > -1;
  const pkcs8 = await crypto.subtle.importKey("pkcs8", pem_to_der(rsaKeys.private, "PRIVATE"), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  const encrypted = needBase64 ? Buffer.from(req.requestText, 'base64') : Buffer.from(req.requestText);
  const result = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, pkcs8, encrypted);
  req.return(200, Buffer.from(result));
}

function entrypoint(r) {
  r.headersOut["Content-Type"] = "text/html;charset=UTF-8";

  switch (r.method) {
    case 'GET':
      return r.return(200, [
        '<form action="/" method="post">',
        '<input name="data" value=""/>',
        '<input type="radio" name="action" id="encrypt" value="encrypt" checked="checked"/><label for="encrypt">Encrypt</label>',
        '<input type="radio" name="action" id="decrypt" value="decrypt"/><label for="decrypt">Decrypt</label>',
        '<input type="radio" name="base64" id="base64-on" value="on" checked="checked"/><label for="base64-on">Base64 On</label>',
        '<input type="radio" name="base64" id="base64-off" value="off" /><label for="base64-off">Base64 Off</label>',
        '<button type="submit">Submit</button>',
        '</form>'
      ].join('<br>'));
    case 'POST':
      var body = r.requestBody;
      if (r.headersIn['Content-Type'] != 'application/x-www-form-urlencoded' || !body.length) {
        r.return(401, "Unsupported method\n");
      }

      var params = body.trim().split('&').reduce(function (prev, item) {
        var tmp = item.split('=');
        var key = decodeURIComponent(tmp[0]).trim();
        var val = decodeURIComponent(tmp[1]).trim();
        if (key === 'data' || key === 'action' || key === 'base64') {
          if (val) {
            prev[key] = val;
          }
        }
        return prev;
      }, {});

      if (!params.action || (params.action != 'encrypt' && params.action != 'decrypt')) {
        return r.return(400, 'Invalid Params: `action`.');
      }

      if (!params.base64 || (params.base64 != 'on' && params.base64 != 'off')) {
        return r.return(400, 'Invalid Params: `base64`.');
      }

      if (!params.data) {
        return r.return(400, 'Invalid Params: `data`.');
      }

      function response_cb(res) {
        r.return(res.status, res.responseBody);
      }

      return r.subrequest(`/api/${params.action}${params.base64 === 'on' ? '?base64=1' : ''}`, { method: 'POST', body: params.data }, response_cb)
    default:
      return r.return(400, "Unsupported method\n");
  }
}



async function auto(req) {
  req.headersOut["Content-Type"] = "text/html;charset=UTF-8";

  function randomSource() {
    const sources = ["/remote/need-encrypt", "/remote/need-decrypt"];
    return sources[Math.floor(Math.random() * sources.length)];
  }

  async function autoCalc(res) {
    const isEncoded = res.headersOut['Encode-State'] == "ON";
    const remoteRaw = res.responseText;
    if (isEncoded) {
      const pkcs8 = await crypto.subtle.importKey("pkcs8", pem_to_der(rsaKeys.private, "PRIVATE"), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
      const encrypted = Buffer.from(remoteRaw, 'base64');
      const result = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, pkcs8, encrypted);
      req.return(200, [
        "<h2>原始内容</h2>",
        `<code>${remoteRaw}</code>`,
        "<h2>处理后的内容</h2>",
        `<code>${Buffer.from(result)}</code>`
      ].join(""));
    } else {
      const spki = await crypto.subtle.importKey("spki", pem_to_der(rsaKeys.public, "PUBLIC"), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
      const dataEncrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, spki, remoteRaw);
      req.return(200, [
        "<h2>原始内容</h2>",
        `<code>${remoteRaw}</code>`,
        "<h2>处理后的内容</h2>",
        `<code>${Buffer.from(dataEncrypted).toString("base64")}</code>`
      ].join(""));
    }
  }

  req.subrequest(randomSource(), { method: "GET" }, autoCalc)
}


export default { encrypt, decrypt, entrypoint, auto };
