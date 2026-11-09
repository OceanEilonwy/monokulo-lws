#!/usr/bin/ucode
// One HTTP request for the LuCI page's backend (rpcd.uc), as a process of
// its own: GET, or POST a JSON body, to a URL on this router, and print
// what came back as JSON: {"status": 200, "body": "..."}, or
// {"error": "..."} when nothing did.
//
// Why not uclient-fetch: it drops the body of an answer with an error
// status, and the server's refusals (a view key that doesn't match its
// address, say) are in that body. Why a process of its own: the uclient
// module is driven by uloop, and rpcd's plugin runs inside rpcd's own loop.
//
//   ucode http.uc GET <url>
//   ucode http.uc POST <url> <file holding the JSON body>
//
// An https URL is accepted without checking the certificate: it is this
// router's own listener, reached on loopback.

'use strict';

import { readfile } from 'fs';
import * as uloop from 'uloop';
import * as uclient from 'uclient';

// uclient's error codes (uclient.h).
const ERRORS = [ 'the connection was refused', 'the connection timed out', 'the certificate is invalid',
	'the certificate is for another name', 'no TLS support' ];

function answer(what) {
	print(sprintf('%J\n', what));
	exit(0);
}

const method = ARGV[0], url = ARGV[1], file = ARGV[2];
if (!(method in [ 'GET', 'POST' ]) || !url)
	answer({ error: 'usage: http.uc GET|POST <url> [body file]' });

let body = null;
if (method == 'POST') {
	body = file ? readfile(file) : null;
	if (body == null)
		answer({ error: `couldn't read the request body ${file}` });
}

let result = { status: 0, body: '' };
const cl = uclient.new(url, null, {
	header_done: function() {
		result.status = this.status().status;
	},
	data_read: function() {
		let chunk;
		while ((chunk = this.read()) != null)
			result.body += chunk;
	},
	data_eof: function() {
		uloop.end();
	},
	error: function(code) {
		result.error = ERRORS[code] ?? `connection error ${code}`;
		uloop.end();
	}
});
if (!cl)
	answer({ error: `not a URL this can fetch: ${url}` });
if (index(url, 'https://') == 0)
	cl.ssl_init({ verify: false });
cl.set_timeout(10000);
if (!cl.connect())
	answer({ error: `couldn't connect to ${url}` });

const request = { headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' } };
if (body != null)
	request.post_data = body;
if (!cl.request(method, request))
	answer({ error: `couldn't send the request to ${url}` });

// uloop.run(timeout) makes one pass of the loop; run() runs until end().
uloop.timer(15000, function() {
	if (!result.error)
		result.error = `no answer from ${url} within 15 seconds`;
	uloop.end();
});
uloop.run();
answer(result);
