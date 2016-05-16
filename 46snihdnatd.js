#!/usr/bin/env nodejs
var net = require('net');
var http = require('http');
var dns = require('dns');
var Parser = require('binary-parser').Parser;
var Promise = require('promise');


var Extension = Parser.start()
    .uint16('type')
    .uint16('length')
    .buffer('buffer', {length: 'length'})
    ;

var sniHeaderParser = new Parser()
    .uint16('length')
    .buffer('buffer', {length: 'length'})
    ;

var Sni = Parser.start()
    .uint8('type')
    .uint16('length')
    .string('value', {length: 'length'})
    ;

var helloParser = new Parser()
    .uint8('handshake')
    .buffer('version', {length: 2})
    .skip(2)
    .uint8('handshake_type')
    .skip(3)
    .buffer('version2', {length: 2})
    .skip(32)
    .uint8('session_len')
    .skip('session_len')
    .uint16('cipher_len')
    .skip('cipher_len')
    .uint8('comp_len')
    .skip('comp_len')
    .uint16('ext_len')
    .buffer('ext', {length: 'ext_len'});
    ;

function extractSni(connection) {
    return new Promise(function(resolve, reject) {
        var buffer = Buffer([]);

        var onData = function(data) {
            console.log('[ $ ] onData triggerd');
            buffer = Buffer.concat([buffer, data]);
            try {
                var sni = getSni(buffer);
            } catch(err) {
                console.log('[$$$] parsing failed, rejecting');
                return reject();
            }
            if(sni) {
                console.log('[ $ ] sni found', sni);
                connection.removeListener('data', onData);
                return resolve({
                    buffered: buffer,
                    name: sni
                });
            } else {
                console.log('[$$$] invalid sni, rejecting');
                return reject();
            }
        };
        connection.on('data', onData);
    });
};

function getExtensions(buffer) {
    var x = helloParser.parse(buffer);
    return x.ext;

};

function getSni(buffer, length) {
    var hello = helloParser.parse(buffer);
    var offset = 0;

    while(offset < hello.ext_len) {
        var ext = nextExtension(hello.ext, offset);
        offset += 4 + ext.length;

        if(ext.type == 0) {
            var sniHeader = sniHeaderParser.parse(ext.buffer);

            var offset2 = 0;
            while(offset2 < sniHeader.length) {
                var sni = nextSni(sniHeader.buffer, offset2);
                offset2 += 3 + sni.length;
                if(sni.type == 0) {
                    return sni.value;
                }
            }
        }
    }

    return null;
};

function nextExtension(buffer, offset) {
    return new Parser()
        .skip(offset)
        .nest('ext', {
            type: Extension,
        })
        .parse(buffer).ext;
};

function nextSni(buffer, offset) {
    return new Parser()
        .skip(offset)
        .nest('sni', {
            type: Sni,
        })
        .parse(buffer).sni;
};

function dns_resolve(name) {
    return new Promise(function(resolve, reject) {
        console.log('[ $ ] resolving', name);
        dns.resolve(name, 'AAAA', function(err, addresses) {
            if(err || !addresses.length) {
                console.log('[%%%%%%] resolve failed', name, err);
                reject(err);
            } else {
                var address = addresses[0];
                console.log('[ %% ] resolved to %s -> %s', addresses, address);
                resolve(address);
            }
        });
    });
};

var http502 = function(res, msg) {
    res.writeHead(502);
    res.end(res, '46snihdnat: ' + msg + '\n');
};

http.createServer(function(req, res) {
    console.log('[ * ] got http connection');
    dns_resolve(req.headers['host']).then(function(address) {
        var proxy_req = http.request({
            host: address,
            port: 80,
            family: 6,
            method: req.method,
            path: req.url,
            headers: req.headers
        }, function(proxy_res) {
            res.writeHead(proxy_res.statusCode, proxy_res.headers);
            proxy_res.pipe(res);
        })
        .on('error', function() {
            console.log('[///] request failed');
            res.destroy();
        });

        req.pipe(proxy_req);
    }).catch(function(err) {
        console.log('[%%%%%%] resolve failed, closing');
        http502('AAAA lookup failed');
    });
}).listen(8080, function() {
    console.log('[###] waiting for http on :8080');
});

net.createServer(function(c) {
    var client;
    console.log('[ * ] got tls connection');

    var writeback;
    extractSni(c).then(function(sni) {
        writeback = sni.buffered;
        return dns_resolve(sni.name);
    }).then(function(address) {
        console.log('[!!!] connecting to [%s]:%d', address, 443);
        client = net.createConnection(443, address, function() {
            console.log('[ ! ] connected');
            client.write(writeback);
            client.pipe(c);
            c.pipe(client);
        });
        client.on('error', function() {
            console.log('[///] remote disconnected');
            c.end();
        });
        client.on('close', function() {
            console.log('[ / ] connection got closed');
        });
    }).catch(function() {
        console.log('[***] rejecting connection');
        c.end();
    });

    c.on('error', function() {
        console.log('[///] client disconnected');
        if(client) client.end();
        c.end();
    });
}).listen(8443, function() {
    console.log('[###] waiting for sni on :8443');
});
