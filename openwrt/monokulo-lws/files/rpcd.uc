// The backend of Services > Light Wallet Server, over ubus: an rpcd ucode
// plugin installed as /usr/share/rpcd/ucode/monokulo-lws, exposing the
// object monokulo-lws. There is a server per network turned on (mainnet,
// stagenet, testnet), each with its own admin API and key; every method on
// wallets takes {network}, mainnet when left out.
//   status           for each network: whether its server is on and runs,
//                    its build, why it didn't start, and what the server
//                    says of itself and its node (its /daemon_status)
//   accounts         the wallets a server scans and the requests waiting,
//                    from its admin API
//   add_account      {address, view_key, start_height}: a wallet to scan,
//                    from that block (-1: the chain's top)
//   set_status       {addresses, status}: active, inactive or hidden
//   rescan           {addresses, height}
//   remove_accounts  {addresses}: forgotten, with everything scanned
//   requests         {type, addresses, accept}: a create or import request
//                    accepted or rejected
//   restart, reload  the init script's, as LuCI's setInitAction would run
//                    them: the page's ACL grants these instead of
//                    setInitAction, which takes any init script
//   new_admin_key    {network}: a new key for that server's admin API (the
//                    init script's admin_key)
// The admin API is the server's own, on 127.0.0.1 (--admin-listen), with
// the key the init script made in /etc/monokulo-lws/secrets/<network>/, root's alone:
// LuCI can't read it, nor run a command, without this. The HTTP calls go
// through http.uc (see its header), a process of its own, with each
// request body in a root-only folder in memory.

'use strict';

import { readfile, writefile, unlink, mkdir, chmod, access, popen } from 'fs';
import { connect } from 'ubus';
import { cursor } from 'uci';

const NAME = 'monokulo-lws';
const NETWORKS = [ 'mainnet', 'stagenet', 'testnet' ];
// What a network's section leaves out, as the init script takes it.
const DEFAULTS = {
	mainnet: { enabled: '1', port: '8443', admin_port: '8444' },
	stagenet: { enabled: '0', port: '38443', admin_port: '38444' },
	testnet: { enabled: '0', port: '28443', admin_port: '28444' }
};
function key_file(network) {
	return `/etc/${NAME}/secrets/${network}/MONOKULO_LWS_ADMIN_KEY`;
}
const HELPER = `/usr/share/${NAME}/http.uc`;
// The request bodies the helper reads, and why the init script last refused
// to start (check): root's alone and in memory.
const RUN_DIR = `/var/run/${NAME}`;
const STATUSES = [ 'active', 'inactive', 'hidden' ];

// The output and exit code of a command run by the shell, stderr included.
function run(command) {
	const proc = popen(`${command} 2>&1`);
	if (!proc)
		return { output: '', code: -1 };
	const output = proc.read('all') ?? '';
	return { output: trim(output), code: proc.close() };
}

// version= and commit= lines, as the package's version file holds them.
function build(text) {
	const found = {};
	for (let line in split(text ?? '', '\n')) {
		const kv = match(line, /^(version|commit)=(.*)$/);
		if (kv)
			found[kv[1]] = trim(kv[2]);
	}
	return found;
}

function first_line_file(path) {
	const text = readfile(path);
	return text == null ? null : trim(text);
}

// A port from UCI: digits, or the default.
function port_of(value, fallback) {
	return match(value ?? '', /^[0-9]{1,5}$/) ? value : fallback;
}

// The network a request names: one of NETWORKS, mainnet when left out,
// or null.
function network_of(value) {
	if (value == null || value == '')
		return 'mainnet';
	return (type(value) == 'string' && value in NETWORKS) ? value : null;
}

// Where a network's server listens, from UCI: the wallet API's address as
// this router reaches it, and the admin API's; and whether it is on.
function settings(network) {
	const ctx = cursor();
	const shared = (option) => ctx.get(NAME, 'main', option);
	const own = (option) => ctx.get(NAME, network, option) ?? DEFAULTS[network][option];
	const scheme = shared('tls_cert') ? 'https' : 'http';
	let host = '127.0.0.1';
	const listen = shared('listen') ?? 'loopback';
	if (listen == 'lan') {
		const lan = connect()?.call('network.interface.lan', 'status');
		host = lan?.['ipv4-address']?.[0]?.address ?? host;
	}
	return {
		listen,
		enabled: (shared('enabled') ?? '1') != '0' && own('enabled') == '1',
		wallet: `${scheme}://${host}:${port_of(own('port'), DEFAULTS[network].port)}`,
		admin: `${scheme}://127.0.0.1:${port_of(own('admin_port'), DEFAULTS[network].admin_port)}`
	};
}

// One HTTP request through the helper: {status, body} or {error}.
function http(method, url, body) {
	let file = null;
	if (body != null) {
		mkdir(RUN_DIR, 0o700);
		chmod(RUN_DIR, 0o700);
		file = `${RUN_DIR}/request.json`;
		if (writefile(file, body) == null)
			return { error: `couldn't write ${file}` };
		chmod(file, 0o600);
	}
	const res = run(`ucode ${HELPER} ${method} '${url}'${file ? ` '${file}'` : ''}`);
	if (file)
		unlink(file);
	let parsed;
	try {
		parsed = json(res.output);
	}
	catch (e) {
		return { error: `the HTTP helper failed: ${res.output}` };
	}
	return parsed;
}

// An admin API command: {ok: true, result} or {ok: false, code, error},
// the error in the server's own words where it has them.
function admin(network, command, params) {
	const where = settings(network);
	if (!where.enabled)
		return { ok: false, code: 'off', error: `The ${network} server is turned off: turn it on under Settings.` };
	const key = trim(readfile(key_file(network)) ?? '');
	if (!key)
		return { ok: false, code: 'no_key', error: 'There is no admin key yet: the server makes one when it first starts.' };
	const res = http('POST', `${where.admin}/${command}`, sprintf('%J', { auth: key, params: params ?? {} }));
	if (res.error)
		return { ok: false, code: 'unreachable', error: `Couldn't reach the ${network} server's admin API on this router: ${res.error}.` };
	if (res.status == 403)
		return { ok: false, code: 'refused', error: `The server refused the admin key in ${key_file(network)}: make a new one.` };
	if (res.status != 200)
		return { ok: false, code: 'error', error: trim(res.body) || `the server answered HTTP ${res.status}` };
	try {
		return { ok: true, result: json(res.body) };
	}
	catch (e) {
		return { ok: false, code: 'error', error: "the server's answer wasn't JSON" };
	}
}

// The service's init script run with action, as LuCI's setInitAction
// runs one: whether it succeeded.
function init_action(action) {
	return { result: system(`/etc/init.d/${NAME} ${action} >/dev/null 2>&1`) == 0 };
}

// A list of addresses from a request: strings, no more than a few hundred.
function addresses_of(value) {
	if (type(value) != 'array' || length(value) == 0 || length(value) > 500)
		return null;
	for (let a in value)
		if (type(a) != 'string' || length(a) < 10 || length(a) > 200 || match(a, /[^0-9A-Za-z]/))
			return null;
	return value;
}

function bad(error) {
	return { ok: false, code: 'bad', error };
}

const NO_NETWORK = 'The network is mainnet, stagenet or testnet.';

// A network's part of the status.
function network_status(instances, network) {
	const instance = instances?.[network];
	const running = instance?.running == true;
	const where = settings(network);
	let server = null;
	if (running) {
		const res = http('GET', `${where.wallet}/daemon_status`);
		if (res.status == 200) {
			try {
				server = json(res.body);
			}
			catch (e) {
				server = null;
			}
		}
	}
	return {
		enabled: where.enabled,
		running,
		running_build: running ? { version: instance.data?.version, commit: instance.data?.commit } : null,
		check_error: first_line_file(`${RUN_DIR}/check.${network}`),
		admin_key: access(key_file(network)) == true,
		wallet_url: where.wallet,
		admin_url: where.admin,
		server
	};
}

const methods = {
	status: {
		call: function() {
			const ubus = connect();
			const listed = ubus?.call('service', 'list', { name: NAME });
			const instances = listed?.[NAME]?.instances;
			const networks = {};
			let running = false;
			for (let network in NETWORKS) {
				networks[network] = network_status(instances, network);
				running = running || networks[network].running;
			}
			// The last lines of the servers' and their init script's log.
			const log = run(`logread -e '${NAME}' | tail -n 20`);
			return {
				running,
				installed: build(readfile(`/usr/share/${NAME}/version`)),
				check_error: first_line_file(`${RUN_DIR}/check`),
				networks,
				log: log.code == 0 && length(log.output) ? split(log.output, '\n') : []
			};
		}
	},

	accounts: {
		args: { network: 'network' },
		call: function(request) {
			const network = network_of(request.args.network);
			if (!network)
				return bad(NO_NETWORK);
			const accounts = admin(network, 'list_accounts');
			if (!accounts.ok)
				return accounts;
			const requests = admin(network, 'list_requests');
			return {
				ok: true,
				accounts: accounts.result,
				requests: requests.ok ? requests.result : { create: [], import: [] }
			};
		}
	},

	add_account: {
		args: { network: 'network', address: 'address', view_key: 'view_key', start_height: 0 },
		call: function(request) {
			const network = network_of(request.args.network);
			if (!network)
				return bad(NO_NETWORK);
			const address = request.args.address, key = request.args.view_key, height = request.args.start_height;
			if (type(address) != 'string' || !length(trim(address)))
				return bad('The address is missing.');
			if (type(key) != 'string' || !match(key, /^[0-9a-fA-F]{64}$/))
				return bad('The private view key is 64 hexadecimal characters.');
			const added = admin(network, 'add_account', { address: trim(address), key: lc(key) });
			if (!added.ok)
				return added;
			// The server starts a new account at the chain's top; a start
			// height is a rescan from there.
			if (type(height) == 'int' && height >= 0) {
				const scanned = admin(network, 'rescan', { height, addresses: [ trim(address) ] });
				if (!scanned.ok)
					return { ok: false, code: scanned.code, error: `Added, but not set to scan from ${height}: ${scanned.error}` };
			}
			return { ok: true };
		}
	},

	set_status: {
		args: { network: 'network', addresses: [], status: 'status' },
		call: function(request) {
			const network = network_of(request.args.network);
			if (!network)
				return bad(NO_NETWORK);
			const addresses = addresses_of(request.args.addresses);
			if (!addresses)
				return bad('No addresses.');
			if (!(request.args.status in STATUSES))
				return bad('The status is active, inactive or hidden.');
			return admin(network, 'modify_account_status', { status: request.args.status, addresses });
		}
	},

	rescan: {
		args: { network: 'network', addresses: [], height: 0 },
		call: function(request) {
			const network = network_of(request.args.network);
			if (!network)
				return bad(NO_NETWORK);
			const addresses = addresses_of(request.args.addresses);
			if (!addresses)
				return bad('No addresses.');
			if (type(request.args.height) != 'int' || request.args.height < 0)
				return bad('The height is a block number.');
			return admin(network, 'rescan', { height: request.args.height, addresses });
		}
	},

	remove_accounts: {
		args: { network: 'network', addresses: [] },
		call: function(request) {
			const network = network_of(request.args.network);
			if (!network)
				return bad(NO_NETWORK);
			const addresses = addresses_of(request.args.addresses);
			if (!addresses)
				return bad('No addresses.');
			return admin(network, 'remove_accounts', { addresses });
		}
	},

	requests: {
		args: { network: 'network', type: 'type', addresses: [], accept: false },
		call: function(request) {
			const network = network_of(request.args.network);
			if (!network)
				return bad(NO_NETWORK);
			const addresses = addresses_of(request.args.addresses);
			if (!addresses)
				return bad('No addresses.');
			if (!(request.args.type in [ 'create', 'import' ]))
				return bad('The type is create or import.');
			return admin(network, request.args.accept ? 'accept_requests' : 'reject_requests',
				{ type: request.args.type, addresses });
		}
	},

	restart: {
		call: function() {
			return init_action('restart');
		}
	},

	reload: {
		call: function() {
			return init_action('reload');
		}
	},

	new_admin_key: {
		args: { network: 'network' },
		call: function(request) {
			const network = network_of(request.args.network);
			if (!network)
				return bad(NO_NETWORK);
			const made = run(`/etc/init.d/${NAME} admin_key ${network}`);
			return { ok: made.code == 0, error: made.code == 0 ? null : made.output };
		}
	}
};

return { [NAME]: methods };
