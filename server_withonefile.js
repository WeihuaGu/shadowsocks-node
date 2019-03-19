const merge = function(left, right, comparison) {
  const result = new Array();
  while (left.length > 0 && right.length > 0) {
    if (comparison(left[0], right[0]) <= 0) {
      result.push(left.shift());
    } else {
      result.push(right.shift());
    }
  }
  while (left.length > 0) {
    result.push(left.shift());
  }
  while (right.length > 0) {
    result.push(right.shift());
  }
  return result;
};
var merge_sort = function(array, comparison) {
  if (array.length < 2) {
    return array;
  }
  const middle = Math.ceil(array.length / 2);
  return merge(
    merge_sort(array.slice(0, middle), comparison),
    merge_sort(array.slice(middle), comparison),
    comparison
  );
};

const crypto = require('crypto');

const int32Max = Math.pow(2, 32);

const cachedTables = {}; // password: [encryptTable, decryptTable]

const getTable = function(key) {
  if (cachedTables[key]) {
    return cachedTables[key];
  }
  console.log('calculating ciphers');
  let table = new Array(256);
  const decrypt_table = new Array(256);
  const md5sum = crypto.createHash('md5');
  md5sum.update(key);
  const hash = new Buffer(md5sum.digest(), 'binary');
  const al = hash.readUInt32LE(0);
  const ah = hash.readUInt32LE(4);
  let i = 0;

  while (i < 256) {
    table[i] = i;
    i++;
  }
  i = 1;

  while (i < 1024) {
    table = merge_sort(
      table,
      (x, y) =>
        ((ah % (x + i)) * int32Max + al) % (x + i) -
        ((ah % (y + i)) * int32Max + al) % (y + i)
    );
    i++;
  }
  i = 0;
  while (i < 256) {
    decrypt_table[table[i]] = i;
    ++i;
  }
  const result = [table, decrypt_table];
  cachedTables[key] = result;
  return result;
};

const substitute = function(table, buf) {
  let i = 0;

  while (i < buf.length) {
    buf[i] = table[buf[i]];
    i++;
  }
  return buf;
};

const bytes_to_key_results = {};

const EVP_BytesToKey = function(password, key_len, iv_len) {
  if (bytes_to_key_results[`${password}:${key_len}:${iv_len}`]) {
    return bytes_to_key_results[`${password}:${key_len}:${iv_len}`];
  }
  const m = [];
  let i = 0;
  let count = 0;
  while (count < key_len + iv_len) {
    const md5 = crypto.createHash('md5');
    let data = password;
    if (i > 0) {
      data = Buffer.concat([m[i - 1], password]);
    }
    md5.update(data);
    const d = md5.digest();
    m.push(d);
    count += d.length;
    i += 1;
  }
  const ms = Buffer.concat(m);
  const key = ms.slice(0, key_len);
  const iv = ms.slice(key_len, key_len + iv_len);
  bytes_to_key_results[password] = [key, iv];
  return [key, iv];
};

const method_supported = {
  'aes-128-cfb': [16, 16],
  'aes-192-cfb': [24, 16],
  'aes-256-cfb': [32, 16],
  'bf-cfb': [16, 8],
  'camellia-128-cfb': [16, 16],
  'camellia-192-cfb': [24, 16],
  'camellia-256-cfb': [32, 16],
  'cast5-cfb': [16, 8],
  'des-cfb': [8, 8],
  'idea-cfb': [16, 8],
  'rc2-cfb': [16, 8],
  rc4: [16, 0],
  'rc4-md5': [16, 16],
  'seed-cfb': [16, 16]
};

const create_rc4_md5_cipher = function(key, iv, op) {
  const md5 = crypto.createHash('md5');
  md5.update(key);
  md5.update(iv);
  const rc4_key = md5.digest();
  if (op === 1) {
    return crypto.createCipheriv('rc4', rc4_key, '');
  } else {
    return crypto.createDecipheriv('rc4', rc4_key, '');
  }
};

class Encryptor {
  constructor(key, method) {
    this.key = key;
    this.method = method;
    this.iv_sent = false;
    if (this.method === 'table') {
      this.method = null;
    }
    if (this.method) {
      this.cipher = this.get_cipher(
        this.key,
        this.method,
        1,
        crypto.randomBytes(32)
      );
    } else {
      [this.encryptTable, this.decryptTable] = getTable(this.key);
    }
  }

  get_cipher_len(method) {
    method = method.toLowerCase();
    return method_supported[method];
  }

  get_cipher(password, method, op, iv) {
    method = method.toLowerCase();
    password = new Buffer(password, 'binary');
    const m = this.get_cipher_len(method);
    if (m) {
      const [key, iv_] = EVP_BytesToKey(password, m[0], m[1]);
      if (!iv) {
        iv = iv_;
      }
      if (op === 1) {
        this.cipher_iv = iv.slice(0, m[1]);
      }
      iv = iv.slice(0, m[1]);
      if (method === 'rc4-md5') {
        return create_rc4_md5_cipher(key, iv, op);
      } else {
        if (op === 1) {
          return crypto.createCipheriv(method, key, iv);
        } else {
          return crypto.createDecipheriv(method, key, iv);
        }
      }
    }
  }

  encrypt(buf) {
    if (this.method) {
      const result = this.cipher.update(buf);
      if (this.iv_sent) {
        return result;
      } else {
        this.iv_sent = true;
        return Buffer.concat([this.cipher_iv, result]);
      }
    } else {
      return substitute(this.encryptTable, buf);
    }
  }

  decrypt(buf) {
    if (this.method) {
      let result;
      if (!this.decipher) {
        const decipher_iv_len = this.get_cipher_len(this.method)[1];
        const decipher_iv = buf.slice(0, decipher_iv_len);
        this.decipher = this.get_cipher(this.key, this.method, 0, decipher_iv);
        result = this.decipher.update(buf.slice(decipher_iv_len));
        return result;
      } else {
        result = this.decipher.update(buf);
        return result;
      }
    } else {
      return substitute(this.decryptTable, buf);
    }
  }
}

exports.Encryptor = Encryptor;
exports.getTable = getTable;

const net = require('net');
const fs = require('fs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const WebSocketServer = WebSocket.Server;
const parseArgs = require('minimist');


const options = {
  alias: {
    b: 'local_address',
    r: 'remote_port',
    k: 'password',
    c: 'config_file',
    m: 'method'
  },
  string: ['local_address', 'password', 'method', 'config_file'],
  default: {
    config_file:{
  "server": "127.0.0.1",
  "local_address": "127.0.0.1",
  "scheme": "ws",
  "local_port": 1080,
  "remote_port": 8080,
  "password": "abcd4320",
  "timeout": 600,
  "method": "rc4-md5"
}
  }
};

const inetNtoa = buf => buf[0] + '.' + buf[1] + '.' + buf[2] + '.' + buf[3];

const configFromArgs = parseArgs(process.argv.slice(2), options);
const configFile = configFromArgs.config_file;
const configContent = {
  "server": "127.0.0.1",
  "local_address": "127.0.0.1",
  "scheme": "ws",
  "local_port": 1080,
  "remote_port": 8080,
  "password": "abcd4320",
  "timeout": 600,
  "method": "rc4-md5"
};
const config =configContent;

if (process.env.PORT) {
  config['remote_port'] = +process.env.PORT;
}
if (process.env.KEY) {
  config['password'] = process.env.KEY;
}
if (process.env.METHOD) {
  config['method'] = process.env.METHOD;
}

for (let k in configFromArgs) {
  const v = configFromArgs[k];
  config[k] = v;
}

const timeout = Math.floor(config.timeout * 1000);
const LOCAL_ADDRESS = config.local_address;
const PORT = config.remote_port;
const KEY = config.password;
let METHOD = config.method;

if (['', 'null', 'table'].includes(METHOD.toLowerCase())) {
  METHOD = null;
}

const server = http.createServer(function(req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('asdf.');
});

const wss = new WebSocketServer({ server });

wss.on('connection', function(ws) {
  console.log('server connected');
  console.log('concurrent connections:', wss.clients.size);
  const encryptor = new Encryptor(KEY, METHOD);
  let stage = 0;
  let headerLength = 0;
  let remote = null;
  let cachedPieces = [];
  let addrLen = 0;
  let remoteAddr = null;
  let remotePort = null;
  ws.on('message', function(data, flags) {
    data = encryptor.decrypt(data);
    if (stage === 5) {
      remote.write(data);
    }
    if (stage === 0) {
      try {
        const addrtype = data[0];
        if (addrtype === 3) {
          addrLen = data[1];
        } else if (addrtype !== 1) {
          console.warn(`unsupported addrtype: ${addrtype}`);
          ws.close();
          return;
        }
        // read address and port
        if (addrtype === 1) {
          remoteAddr = inetNtoa(data.slice(1, 5));
          remotePort = data.readUInt16BE(5);
          headerLength = 7;
        } else {
          remoteAddr = data.slice(2, 2 + addrLen).toString('binary');
          remotePort = data.readUInt16BE(2 + addrLen);
          headerLength = 2 + addrLen + 2;
        }

        // connect remote server
        remote = net.connect(remotePort, remoteAddr, function() {
          console.log('connecting', remoteAddr);
          let i = 0;

          while (i < cachedPieces.length) {
            const piece = cachedPieces[i];
            remote.write(piece);
            i++;
          }
          cachedPieces = null; // save memory
          stage = 5;
        });
        remote.on('data', function(data) {
          data = encryptor.encrypt(data);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(data, { binary: true });
          }
        });

        remote.on('end', function() {
          ws.close();
          console.log('remote disconnected');
        });

        remote.on('error', function(e) {
          ws.terminate();
          console.log(`remote: ${e}`);
        });

        remote.setTimeout(timeout, function() {
          console.log('remote timeout');
          remote.destroy();
          ws.close();
        });

        if (data.length > headerLength) {
          // make sure no data is lost
          let buf = new Buffer(data.length - headerLength);
          data.copy(buf, 0, headerLength);
          cachedPieces.push(buf);
          buf = null;
        }
        stage = 4;
      } catch (error) {
        // may encouter index out of range
        const e = error;
        console.warn(e);
        if (remote) {
          remote.destroy();
        }
        ws.close();
      }
    } else if (stage === 4) {
      // remote server not connected
      // cache received buffers
      // make sure no data is lost
      cachedPieces.push(data);
    }
  });

  ws.on('ping', () => ws.pong('', null, true));

  ws.on('close', function() {
    console.log('server disconnected');
    console.log('concurrent connections:', wss.clients.size);
    if (remote) {
      remote.destroy();
    }
  });

  ws.on('error', function(e) {
    console.warn(`server: ${e}`);
    console.log('concurrent connections:', wss.clients.size);
    if (remote) {
      remote.destroy();
    }
  });
});

server.listen(PORT, LOCAL_ADDRESS, function() {
  const address = server.address();
  console.log('server listening at', address);
});

server.on('error', function(e) {
  if (e.code === 'EADDRINUSE') {
    console.log('address in use, aborting');
  }
  process.exit(1);
});
