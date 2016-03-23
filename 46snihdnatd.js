#!/usr/bin/env nodejs
var net = require('net');
var dns = require('dns');
var Parser = require('binary-parser').Parser;


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

function extractSni(connection, cb) {
	var buffer = Buffer([]);

	var onData = function(data) {
		console.log('[ $ ] onData triggerd');
		buffer = Buffer.concat([buffer, data]);
		var sni = getSni(buffer);
		if(sni) {
			console.log('[ $ ] sni found: %s, finishing', sni);
			connection.removeListener('data', onData);
			cb(buffer, sni);
		}
	};
	connection.on('data', onData);
};

function getExtensions(buffer) {
	var x = helloParser.parse(buffer);
	return x.ext;

};

function getSni(buffer, length) {
	var hello = helloParser.parse(buffer);
	var offset = 0;

	while(offset < hello.ext_len) {
		var ext	= nextExtension(hello.ext, offset);
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

net.createServer(function(c) {
	extractSni(c, function(buffered, name) {
		var client;
		dns.resolve(name, 'AAAA', function(err, addresses) {
			if(err || !addresses) return console.log('[%%%%%%] didn\'t resolve', err);
			console.log('[ % ] resolved to %s', addresses);
			console.log('[!!!] connecting to %s:%d', addresses[0], 443);
			client = net.createConnection(443, addresses[0], function() {
				console.log('[ ! ] connected');
				client.write(buffered);
				client.pipe(c);
				c.pipe(client);
			});
			client.on('error', function() {
				console.log('[///] closing connection');
				client.close();
				c.close();
			});
			client.on('close', function() {
				console.log('[ / ] connection got closed');
			});
		});

		c.on('error', function() {
			if(client && client.close) client.close();
			if(c && c.close) c.close();
		});
	});

	console.log('[ + ] got client');
}).listen(8443, function() {
	console.log('[###] waiting...')
});
