'use strict';
'require view';
'require form';
'require rpc';
'require uci';
'require ui';
'require dom';

// Services > Light Wallet Server: whether monokulo-lws runs and how it is
// keeping up with the chain (from its own /daemon_status), the wallets it
// scans (added, paused, hidden, rescanned or removed through the server's
// admin API on this router), and every setting it starts with, in tabs.
// Save & Apply restarts the server on the new settings. The backend is the
// package's rpcd plugin (ubus object monokulo-lws).

var NAME = 'monokulo-lws';
// Where a build's commit link points.
var REPOSITORY = 'https://github.com/OceanEilonwy/monokulo-lws';

var callStatus = rpc.declare({ object: NAME, method: 'status', expect: { '': {} } });
var callAccounts = rpc.declare({ object: NAME, method: 'accounts', expect: { '': {} } });
var callAddAccount = rpc.declare({ object: NAME, method: 'add_account',
	params: [ 'address', 'view_key', 'start_height' ], expect: { '': {} } });
var callSetStatus = rpc.declare({ object: NAME, method: 'set_status', params: [ 'addresses', 'status' ], expect: { '': {} } });
var callRescan = rpc.declare({ object: NAME, method: 'rescan', params: [ 'addresses', 'height' ], expect: { '': {} } });
var callRemove = rpc.declare({ object: NAME, method: 'remove_accounts', params: [ 'addresses' ], expect: { '': {} } });
var callRequests = rpc.declare({ object: NAME, method: 'requests', params: [ 'type', 'addresses', 'accept' ], expect: { '': {} } });
var callNewAdminKey = rpc.declare({ object: NAME, method: 'new_admin_key', expect: { '': {} } });
var callUciCommit = rpc.declare({ object: 'uci', method: 'commit', params: [ 'config' ] });
// Its own init script's actions, through its backend: the page's ACL
// grants these, not LuCI's setInitAction, which takes any service.
var callRestart = rpc.declare({ object: NAME, method: 'restart', expect: { result: false } });
var callReload = rpc.declare({ object: NAME, method: 'reload', expect: { result: false } });

function text(value) {
	return document.createTextNode(value == null ? '' : String(value));
}

// A build to read: the version, and the start of its commit linked to it.
function describe(b) {
	var nodes = [ E('code', {}, [ text(b.version) ]) ];
	if (/^[0-9a-f]{40}$/.test(b.commit || ''))
		nodes.push(' · ' + _('commit') + ' ', E('a', {
			href: REPOSITORY + '/commit/' + b.commit, target: '_blank', rel: 'noreferrer'
		}, [ E('code', {}, [ text(b.commit.substring(0, 12)) ]) ]));
	return E('span', {}, nodes);
}

// A Monero address, shortened to read in a table; the whole in its title.
function shortAddress(address) {
	address = String(address || '');
	var node = E('code', { 'title': address, 'style': 'cursor:help' },
		[ text(address.length > 24 ? address.substring(0, 12) + '…' + address.substring(address.length - 8) : address) ]);
	return node;
}

// When something happened (Unix seconds), as how long ago.
function ago(at) {
	var seconds = Math.max(0, Math.floor(Date.now() / 1000) - at);
	return _('%s ago').format('%t'.format(seconds));
}

function showError(title, e) {
	ui.addNotification(null, E('p', {}, [ text(title + ': ' + (e.message || e)) ]), 'danger');
}

// Save, commit, then restart the server on the new settings (through the
// page's own backend, so a login with this page's ACL alone can).
function commitThenReload() {
	return callUciCommit(NAME).then(function() {
		return callReload();
	}).then(function() {
		window.setTimeout(function() { window.location.reload(); }, 1500);
	});
}

// ---- the wallets ----------------------------------------------------------

var WALLET_STATES = {
	active: _('Scanned'),
	inactive: _('Paused'),
	hidden: _('Hidden')
};

// A field of a dialog: its label, input and help.
function field(label, input, help) {
	return E('div', { 'style': 'margin-bottom:1em' }, [
		E('label', { 'style': 'display:block;font-weight:bold;margin-bottom:.25em' }, [ label ]),
		input,
		help ? E('div', { 'class': 'cbi-value-description' }, [ help ]) : ''
	]);
}

// A dialog with Cancel and an action button; `submit` returns a promise of
// the backend's answer, and the dialog shows a refusal where it is.
function dialog(title, body, action, submit) {
	var error = E('p', { 'class': 'alert-message warning', 'style': 'display:none' });
	ui.showModal(title, body.concat([
		error,
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]), ' ',
			E('button', {
				'class': 'btn cbi-button-action important',
				'click': ui.createHandlerFn(this, function() {
					error.style.display = 'none';
					return Promise.resolve(submit()).then(function(res) {
						if (res === false)
							return;
						if (!res.ok) {
							dom.content(error, [ text(res.error || _('The server refused it.')) ]);
							error.style.display = '';
							return;
						}
						ui.hideModal();
					}).catch(function(e) {
						dom.content(error, [ text(e.message || e) ]);
						error.style.display = '';
					});
				})
			}, [ action ])
		])
	]));
}

// The wallets panel: the table of wallets the server scans, the requests
// waiting on the operator (with --create approve or --import approve), and
// what to do about either. Redrawn in place after each action.
function Wallets(view) {
	this.view = view;
	this.node = E('div', { 'class': 'cbi-section-node' });
}

Wallets.prototype = {
	refresh: function() {
		var self = this;
		return callAccounts().then(function(data) {
			self.render(data || {});
		}).catch(function(e) {
			self.render({ ok: false, error: e.message || String(e) });
		});
	},

	// An action on the server, then the table again.
	act: function(promise, failed) {
		var self = this;
		return promise.then(function(res) {
			if (!res || !res.ok)
				throw new Error((res && res.error) || _('the server refused it'));
			return self.refresh();
		}).catch(function(e) {
			showError(failed, e);
			return self.refresh();
		});
	},

	add: function() {
		var self = this;
		var address = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'style': 'width:100%',
			'autocomplete': 'off', 'spellcheck': 'false', 'placeholder': _('The wallet’s primary address') });
		var key = E('input', { 'type': 'password', 'class': 'cbi-input-password', 'style': 'width:100%',
			'autocomplete': 'off', 'placeholder': _('64 hexadecimal characters') });
		var height = E('input', { 'type': 'number', 'class': 'cbi-input-text', 'style': 'width:100%',
			'min': '0', 'step': '1', 'placeholder': _('Empty: from the chain’s top block') });
		dialog(_('Add a wallet'), [
			E('p', {}, _('The server scans the chain for this wallet with its private view key: what the wallet receives and, with the wallet’s help, what it spends. The spend key stays in the wallet, which signs on its own; the server never sees it.')),
			field(_('Address'), address),
			field(_('Private view key'), key,
				_('In Fob: Settings › Keys. The key goes to the server on this router alone; the browser keeps it no longer than this dialog is open.')),
			field(_('Scan from block'), height,
				_('The height of the wallet’s first payment, or a little before it: the server looks at every block from there, which takes a while for an old wallet. Empty starts at the chain’s top, which suits a new wallet.'))
		], _('Add'), function() {
			var a = address.value.trim(), k = key.value.trim(), h = height.value.trim();
			if (!a)
				return { ok: false, error: _('The address is missing.') };
			if (!/^[0-9a-fA-F]{64}$/.test(k))
				return { ok: false, error: _('The private view key is 64 hexadecimal characters.') };
			if (h !== '' && !/^[0-9]+$/.test(h))
				return { ok: false, error: _('The block is a number.') };
			return callAddAccount(a, k, h === '' ? -1 : parseInt(h, 10)).then(function(res) {
				if (res && res.ok)
					self.refresh();
				return res;
			});
		});
		address.focus();
	},

	rescan: function(account) {
		var self = this;
		var height = E('input', { 'type': 'number', 'class': 'cbi-input-text', 'style': 'width:100%',
			'min': '0', 'step': '1', 'value': String(Math.max(0, (account.scan_height || 0) - 1000)) });
		dialog(_('Rescan a wallet'), [
			E('p', {}, [ _('Scan again for '), shortAddress(account.address), _(' from a block: what the server found from there on is forgotten and found afresh. For a wallet restored from its seed, its first payment’s block or a little before.') ]),
			field(_('From block'), height)
		], _('Rescan'), function() {
			var h = height.value.trim();
			if (!/^[0-9]+$/.test(h))
				return { ok: false, error: _('The block is a number.') };
			return callRescan([ account.address ], parseInt(h, 10)).then(function(res) {
				if (res && res.ok)
					self.refresh();
				return res;
			});
		});
	},

	setStatus: function(account, status) {
		return this.act(callSetStatus([ account.address ], status), _('Couldn’t change the wallet'));
	},

	remove: function(account) {
		if (!window.confirm(_('Remove this wallet from the server?\n\nIts view key and everything scanned for it are forgotten here. The wallet itself is untouched: it can be added again, and scanned again, any time.')))
			return;
		return this.act(callRemove([ account.address ]), _('Couldn’t remove the wallet'));
	},

	request: function(kind, row, accept) {
		return this.act(callRequests(kind, [ row.address ], accept),
			accept ? _('Couldn’t accept the request') : _('Couldn’t reject the request'));
	},

	newAdminKey: function() {
		var self = this;
		if (!window.confirm(_('Make a new admin key for this page? The server stops for a moment while the key is made with its database, then starts again.')))
			return;
		return callNewAdminKey().then(function(res) {
			if (!res || !res.ok)
				throw new Error((res && res.error) || _('the init script refused'));
			window.setTimeout(function() { window.location.reload(); }, 2000);
		}).catch(function(e) {
			showError(_('Couldn’t make a new admin key'), e);
		});
	},

	// A button that runs fn with args (then the event), spinning meanwhile.
	button: function(label, cls, fn, args) {
		return E('button', {
			'class': 'cbi-button ' + (cls || 'cbi-button-neutral'),
			'style': 'margin-right:.3em',
			'click': ui.createHandlerFn.apply(ui, [ this, fn ].concat(args))
		}, [ label ]);
	},

	walletRow: function(account, status) {
		var actions = [];
		if (status === 'active') {
			actions.push(this.button(_('Rescan…'), 'cbi-button-action', this.rescan, [ account ]));
			actions.push(this.button(_('Pause'), 'cbi-button-neutral', this.setStatus, [ account, 'inactive' ]));
			actions.push(this.button(_('Hide'), 'cbi-button-neutral', this.setStatus, [ account, 'hidden' ]));
		}
		else if (status === 'inactive') {
			actions.push(this.button(_('Resume'), 'cbi-button-action', this.setStatus, [ account, 'active' ]));
			actions.push(this.button(_('Rescan…'), 'cbi-button-neutral', this.rescan, [ account ]));
			actions.push(this.button(_('Hide'), 'cbi-button-neutral', this.setStatus, [ account, 'hidden' ]));
		}
		else {
			actions.push(this.button(_('Show'), 'cbi-button-action', this.setStatus, [ account, 'active' ]));
		}
		actions.push(this.button(_('Remove'), 'cbi-button-remove', this.remove, [ account ]));
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td', 'data-title': _('Address') }, [ shortAddress(account.address) ]),
			E('td', { 'class': 'td', 'data-title': _('State') }, [ WALLET_STATES[status] || status ]),
			E('td', { 'class': 'td', 'data-title': _('Scanned to') }, [ text(account.scan_height) ]),
			E('td', { 'class': 'td', 'data-title': _('Last asked') }, [ account.access_time ? ago(account.access_time) : _('never') ]),
			E('td', { 'class': 'td cbi-section-actions', 'style': 'white-space:nowrap' }, actions)
		]);
	},

	requestRow: function(kind, row) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td', 'data-title': _('Address') }, [ shortAddress(row.address) ]),
			E('td', { 'class': 'td', 'data-title': _('Asks for') },
				[ kind === 'create' ? _('an account, from the chain’s top') : _('a scan from block 0 (an import)') ]),
			E('td', { 'class': 'td cbi-section-actions' }, [
				this.button(_('Accept'), 'cbi-button-positive', this.request, [ kind, row, true ]),
				this.button(_('Reject'), 'cbi-button-remove', this.request, [ kind, row, false ])
			])
		]);
	},

	render: function(data) {
		var self = this, children = [];
		var toolbar = E('div', { 'class': 'cbi-section-create', 'style': 'margin-bottom:1em' }, [
			E('button', { 'class': 'cbi-button cbi-button-add', 'click': ui.createHandlerFn(this, this.add) }, [ _('Add a wallet…') ]), ' ',
			E('button', { 'class': 'cbi-button cbi-button-neutral', 'click': ui.createHandlerFn(this, this.refresh) }, [ _('Refresh') ])
		]);

		if (!data.ok) {
			children.push(E('p', { 'class': 'alert-message warning' }, [ text(data.error || _('Couldn’t list the wallets.')) ]));
			if (data.code === 'refused')
				children.push(E('p', {}, [
					E('button', { 'class': 'cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, this.newAdminKey) },
						[ _('Make a new admin key') ]),
					' ', _('For a database restored from a backup, or an admin key lost: the server stops for a moment.')
				]));
			else if (data.code === 'unreachable' || data.code === 'no_key')
				children.push(E('p', {}, _('The wallets are listed by the server itself, through its admin API on this router, so it has to be running.')));
			dom.content(this.node, children);
			return;
		}

		var accounts = data.accounts || {}, rows = [];
		[ 'active', 'inactive', 'hidden' ].forEach(function(status) {
			(accounts[status] || []).forEach(function(account) {
				rows.push(self.walletRow(account, status));
			});
		});
		children.push(toolbar);
		if (!rows.length)
			children.push(E('p', {}, _('No wallets yet. Add one here with its address and private view key, or, with “New accounts through /login” set to automatic below, let a wallet register itself: in Fob, Settings › Sync through › this server.')));
		else
			children.push(E('table', { 'class': 'table cbi-section-table' }, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, [ _('Address') ]),
					E('th', { 'class': 'th' }, [ _('State') ]),
					E('th', { 'class': 'th' }, [ _('Scanned to') ]),
					E('th', { 'class': 'th' }, [ _('Last asked') ]),
					E('th', { 'class': 'th cbi-section-actions' }, [ '' ])
				])
			].concat(rows)),
			E('div', { 'class': 'cbi-value-description', 'style': 'margin-top:.5em' },
				_('Scanned: looked for in every new block, and served. Paused: served as it stands, not scanned. Hidden: neither, as if it weren’t there; its history is kept. Remove forgets it whole.')));

		var requests = data.requests || {}, waiting = [];
		[ 'create', 'import' ].forEach(function(kind) {
			(requests[kind] || []).forEach(function(row) {
				waiting.push(self.requestRow(kind, row));
			});
		});
		if (waiting.length)
			children.push(E('h4', { 'style': 'margin-top:1.5em' }, [ _('Waiting for you') ]),
				E('p', {}, _('Wallets that asked the server for an account or an import, held for your word (the policies in Wallets below).')),
				E('table', { 'class': 'table cbi-section-table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, [ _('Address') ]),
						E('th', { 'class': 'th' }, [ _('Asks for') ]),
						E('th', { 'class': 'th cbi-section-actions' }, [ '' ])
					])
				].concat(waiting)));

		dom.content(this.node, children);
	}
};

// ---- the page -------------------------------------------------------------

// What the server says of itself and its node (/daemon_status), to read.
function serverLines(server) {
	var lines = [];
	var node = server.daemon_reachable
		? _('reachable, at block %d%s').format(server.daemon_height, server.daemon_synced ? '' : ' (' + _('still syncing') + ')')
		: _('not reachable: check the node address below, and that monerod is running');
	lines.push(E('div', {}, [ E('strong', {}, [ _('Node') ]), ': ', text(node), ' · ', _('network'), ' ', E('code', {}, [ text(server.network) ]) ]));
	var behind = (server.daemon_height || 0) - (server.scanner_height || 0);
	var scan = _('at block %d').format(server.scanner_height || 0);
	if (behind > 1)
		scan += ' · ' + _('%d blocks behind the node').format(behind);
	else
		scan += ' · ' + _('caught up');
	if (server.scanner_seconds_ago != null)
		scan += ' · ' + _('last step %s').format(ago(Math.floor(Date.now() / 1000) - server.scanner_seconds_ago));
	lines.push(E('div', {}, [ E('strong', {}, [ _('Scanner') ]), ': ', text(scan) ]));
	if (server.scanner_error)
		lines.push(E('div', { 'class': 'alert-message warning', 'style': 'margin:.5em 0' }, [ text(server.scanner_error) ]));
	var engine = server.scanner_engine || {};
	lines.push(E('div', {}, [ E('strong', {}, [ _('Engine') ]), ': ',
		engine.gpu ? _('the GPU %s').format(engine.name) : _('the CPU (monero-oxide); a router has no Vulkan GPU, which is as expected') ]));
	var lanes = server.catch_up_lanes;
	if (Array.isArray(lanes) && lanes.length)
		lines.push(E('div', {}, [ E('strong', {}, [ _('Catching up') ]), ': ',
			_('%d lane(s) bringing wallets with history up to the chain').format(lanes.length) ]));
	return lines;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(NAME),
			L.resolveDefault(callStatus(), {}),
			L.resolveDefault(callAccounts(), { ok: false, error: _('The backend didn’t answer.') })
		]);
	},

	render: function(data) {
		var st = data[1] || {};
		var wallets = new Wallets(this);
		wallets.render(data[2] || {});
		var m, s, o;

		m = new form.Map(NAME, _('Light Wallet Server'),
			_('monokulo-lws scans the chain through your own monerod for every wallet registered with it, by the wallet’s private view key, and answers the light wallet REST API (MyMonero’s, as monero-lws serves it), so a wallet catches up in one request instead of scanning days of blocks itself. A wallet keeps its spend key and signs on its own. Save & Apply restarts the server on the new settings.'));

		// -- status --
		s = m.section(form.NamedSection, 'main', NAME, _('Status'));
		s.addremove = false;

		o = s.option(form.DummyValue, '_status', _('Server'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			var nodes = [ E('strong', {}, [ st.running ? _('Running') : _('Not running') ]) ];
			if (st.check_error)
				nodes.push(E('p', {}, st.running
					? _('It runs on its earlier settings: it refused the ones saved last.')
					: _('It didn’t start:')),
					E('pre', {}, [ text(st.check_error) ]));
			else if (!st.running && uci.get(NAME, 'main', 'enabled') === '0')
				nodes.push(' · ' + _('turned off below'));
			else if (!st.running)
				nodes.push(E('p', {}, _('Not started, or it stopped: the log below says why (a node it couldn’t reach, a setting it refused).')));
			if (st.running && !st.server)
				nodes.push(E('p', {}, _('Starting: it answers once it has asked the node.')));
			if (st.running && st.server)
				nodes = nodes.concat([ E('div', { 'style': 'margin-top:.5em' }, serverLines(st.server)) ]);
			return E('div', {}, nodes);
		};

		o = s.option(form.DummyValue, '_version', _('Version'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			var running = st.running_build || {}, installed = st.installed || {};
			if (!running.version)
				return installed.version
					? E('span', {}, [ describe(installed), ' · ' + _('installed; runs when the server starts') ])
					: _('Unknown: reinstall the package to see it.');
			var nodes = [ describe(running) ];
			if (installed.version && (installed.version !== running.version || installed.commit !== running.commit))
				nodes.push(E('br'), describe(installed), ' ' + _('is installed: restart the server to run it.'));
			return E('span', {}, nodes);
		};

		o = s.option(form.DummyValue, '_listen', _('Wallet API'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			var listen = uci.get(NAME, 'main', 'listen') || 'loopback';
			var port = uci.get(NAME, 'main', 'port') || '8443';
			var scheme = uci.get(NAME, 'main', 'tls_cert') ? 'https' : 'http';
			var nodes = [];
			if (listen === 'loopback')
				nodes.push(E('code', {}, [ text(scheme + '://127.0.0.1:' + port) ]), ' · ',
					_('this router alone: for a TLS proxy on it in front, or try it from the router itself. Choose LAN below for wallets on your network.'));
			else {
				var host = listen === 'lan' && st.wallet_url ? st.wallet_url.replace(/^https?:\/\/|:\d+$/g, '') : window.location.hostname;
				nodes.push(E('code', {}, [ text(scheme + '://' + host + ':' + port) ]), ' · ',
					_('in Fob: Settings › Sync through, this address.'));
				if (scheme === 'http')
					nodes.push(E('p', { 'class': 'alert-message warning', 'style': 'margin:.5em 0' },
						_('Plain HTTP: every request carries a wallet’s view key, so keep this to your own network, or set TLS under Access.')));
			}
			nodes.push(E('div', { 'class': 'cbi-value-description' }, [
				_('The admin API, for this page, is on '), E('code', {}, [ text((st.admin_url || 'http://127.0.0.1:' + (uci.get(NAME, 'main', 'admin_port') || '8444'))) ]),
				_(', this router alone, with the key in '), E('code', {}, [ '/etc/monokulo-lws/secrets/' ]),
				st.admin_key ? '' : ' (' + _('not made yet: the server makes it when it first starts') + ')'
			]));
			return E('div', {}, nodes);
		};

		o = s.option(form.Button, '_restart', _('Restart'),
			_('Stops the server and starts it again with the settings saved here. Wallets syncing through it retry on their own.'));
		o.inputtitle = _('Restart the server');
		o.inputstyle = 'reload';
		o.onclick = function() {
			return callRestart().then(function(ok) {
				if (!ok)
					throw new Error(_('the restart was refused'));
				window.setTimeout(function() { window.location.reload(); }, 1500);
			}).catch(function(e) {
				showError(_('Couldn’t restart the server'), e);
			});
		};

		if (st.log && st.log.length) {
			o = s.option(form.DummyValue, '_log', _('Log'));
			o.rawhtml = true;
			o.cfgvalue = function() {
				return E('details', {}, [
					E('summary', { 'style': 'cursor:pointer' }, [ _('The last lines (logread)') ]),
					E('pre', { 'style': 'white-space:pre-wrap;font-size:90%' }, [ text(st.log.join('\n')) ])
				]);
			};
		}

		// -- wallets --
		s = m.section(form.NamedSection, 'main', NAME, _('Wallets'),
			_('The wallets the server scans for, each by its private view key. The server lists them itself, through its admin API on this router.'));
		s.addremove = false;
		o = s.option(form.DummyValue, '_wallets');
		o.rawhtml = true;
		o.cfgvalue = function() {
			return wallets.node;
		};
		// The whole width for the table: no label column.
		o.render = function() {
			return E('div', { 'class': 'cbi-value' }, [ wallets.node ]);
		};

		// -- settings --
		s = m.section(form.NamedSection, 'main', NAME, _('Settings'),
			_('Every setting here is one of the server’s command line options (<code>monokulo-lws serve --help</code>); only what is set is passed, and the server’s own defaults rule the rest.'));
		s.addremove = false;
		s.tab('general', _('General'));
		s.tab('wallets', _('Wallets'), _('How wallets come to be scanned, and how far the server looks for each.'));
		s.tab('access', _('Access'), _('TLS, proxies and browsers: what reaches the server, and how.'));
		s.tab('limits', _('Limits'), _('Requests and connections the server takes before it refuses; the defaults suit a shop or a small public server.'));
		s.tab('scanning', _('Scanning'), _('How wallets with history are brought up to the chain.'));

		// General
		o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'daemon', _('Node'),
			_('monerod’s RPC address. Your own node: the server trusts what it says, as monero-lws does. A public node works for trying it out.'));
		o.placeholder = 'http://127.0.0.1:18081';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (!value || /^https?:\/\/[^\s/]+(\/.*)?$/.test(value))
				return true;
			return _('An address such as http://127.0.0.1:18081.');
		};

		o = s.taboption('general', form.ListValue, 'network', _('Network'),
			_('Refuse to start if the node is on another network: a guard against pointing a mainnet server at a stagenet node, or the reverse.'));
		o.value('', _('Whatever the node is on'));
		o.value('main', _('Mainnet'));
		o.value('stage', _('Stagenet'));
		o.value('test', _('Testnet'));
		o.default = '';

		o = s.taboption('general', form.ListValue, 'listen', _('Listen on'),
			_('Every request carries a wallet’s private view key: off this router, serve TLS (Access) or put a TLS proxy in front, and open the port in the firewall (the rule Allow-monokulo-lws, off) only if wallets reach it from the internet.'));
		o.value('loopback', _('This router only (127.0.0.1)'));
		o.value('lan', _('LAN only'));
		o.value('all', _('All interfaces'));
		o.default = 'loopback';

		o = s.taboption('general', form.Value, 'port', _('Port'),
			_('The wallet API’s TCP port.'));
		o.datatype = 'port';
		o.placeholder = '8443';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'admin_port', _('Admin port'),
			_('The admin API’s port, on 127.0.0.1 alone, which this page uses. A port of its own, not the wallet API’s.'));
		o.datatype = 'port';
		o.placeholder = '8444';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			var port = this.section.formvalue(section_id, 'port');
			if (value && port && value === port)
				return _('The admin API needs a port of its own.');
			return true;
		};

		o = s.taboption('general', form.Value, 'data_dir', _('Data folder'),
			_('The database, which holds every wallet’s private view key in the clear (as monero-lws keeps them), and the shader cache. Must be on storage, not /tmp; kept across firmware upgrades if left at the default. Back it up, or keep the view keys elsewhere too.'));
		o.placeholder = '/srv/monokulo-lws';
		o.validate = function(section_id, value) {
			if (!value)
				return true;
			if (!/^\/[^\s]*$/.test(value))
				return _('Use an absolute path such as /srv/monokulo-lws.');
			if (/^\/(tmp|var)(\/|$)/.test(value))
				return _('/tmp and /var are in memory: everything there is lost on reboot.');
			return true;
		};

		o = s.taboption('general', form.ListValue, 'log_level', _('Log level'),
			_('How much the server writes to the system log. No view key or address is written at any level.'));
		o.value('error', _('Errors only'));
		o.value('warn', _('Warnings'));
		o.value('info', _('Information'));
		o.value('debug', _('Debugging'));
		o.value('trace', _('Everything'));
		o.default = 'info';

		o = s.taboption('general', form.Value, 'nice', _('Priority (nice)'),
			_('0 is normal, 19 the lowest. Higher gives way to everything else the router does while the server catches up with the chain.'));
		o.datatype = 'range(0,19)';
		o.placeholder = '10';

		o = s.taboption('general', form.Value, 'cpus', _('CPUs'),
			_('Which CPUs the server may use, e.g. <code>2,3</code>, so that scanning leaves the rest for routing. Empty: all of them.'));
		o.placeholder = _('all');
		o.validate = function(section_id, value) {
			if (!value || /^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$/.test(value))
				return true;
			return _('A list such as 2,3 or 1-3.');
		};

		// Wallets
		o = s.taboption('wallets', form.ListValue, 'create', _('New accounts through /login'),
			_('What a wallet that asks for an account gets: one at once (it is scanned from the chain’s top), a place in the queue above for your word, or a refusal. Add wallets here either way.'));
		o.value('auto', _('Made at once'));
		o.value('approve', _('Held for your approval'));
		o.value('off', _('Refused'));
		o.default = 'auto';

		o = s.taboption('wallets', form.ListValue, 'import', _('Imports (a scan from block 0)'),
			_('What a wallet that asks to be scanned from the first block gets: the server’s heaviest request, so held for your word unless you say otherwise.'));
		o.value('approve', _('Held for your approval'));
		o.value('auto', _('Done at once'));
		o.default = 'approve';

		o = s.taboption('wallets', form.Value, 'max_subaddresses', _('Subaddresses per wallet'),
			_('How many subaddresses a wallet may register to be watched. 0 turns the subaddress endpoints off.'));
		o.datatype = 'uinteger';
		o.placeholder = '10000';

		o = s.taboption('wallets', form.Value, 'lookahead', _('Lookahead'),
			_('Subaddresses 0 to N of each wallet’s first account are watched without being asked, as a wallet hands them out.'));
		o.datatype = 'uinteger';
		o.placeholder = '200';

		o = s.taboption('wallets', form.Value, 'scan_interval', _('Scan interval (seconds)'),
			_('How often the server asks the node for new blocks once it has caught up.'));
		o.datatype = 'uinteger';
		o.placeholder = '10';

		// Access
		o = s.taboption('access', form.Value, 'tls_cert', _('TLS certificate'),
			_('A PEM certificate chain on this router: the listeners then speak TLS themselves (1.2 and 1.3). Put it in the data folder, which is the server’s own, e.g. <code>/srv/monokulo-lws/tls/fullchain.pem</code>. A reverse proxy (nginx, caddy) in front is still the recommended setup.'));
		o.placeholder = '/srv/monokulo-lws/tls/fullchain.pem';
		o.validate = function(section_id, value) {
			var key = this.section.formvalue(section_id, 'tls_key');
			if ((value && !key) || (!value && key))
				return _('TLS needs both the certificate and the key.');
			if (value && !/^\/[^\s]+$/.test(value))
				return _('An absolute path on this router.');
			return true;
		};

		o = s.taboption('access', form.Value, 'tls_key', _('TLS private key'),
			_('The PEM private key for the certificate, readable by the server (the data folder is).'));
		o.placeholder = '/srv/monokulo-lws/tls/privkey.pem';
		o.validate = function(section_id, value) {
			if (value && !/^\/[^\s]+$/.test(value))
				return _('An absolute path on this router.');
			return true;
		};

		o = s.taboption('access', form.DynamicList, 'trusted_proxy', _('Trusted proxies'),
			_('Reverse proxies (addresses or CIDR ranges) whose client-address header is believed, for the rate limits. Without any, the header is ignored and the proxy counts as the client.'));
		o.datatype = 'or(ipaddr,cidr)';
		o.placeholder = '127.0.0.1';

		o = s.taboption('access', form.Value, 'client_ip_header', _('Client address header'),
			_('The header a trusted proxy puts the client’s address in; the rightmost address not a trusted proxy’s is the client.'));
		o.placeholder = 'X-Forwarded-For';
		o.validate = function(section_id, value) {
			if (!value || /^[A-Za-z0-9-]+$/.test(value))
				return true;
			return _('A header name such as X-Forwarded-For.');
		};

		o = s.taboption('access', form.DynamicList, 'access_control_origin', _('Browser origins'),
			_('Web wallets allowed to call the API from a browser (CORS), e.g. <code>https://wallet.example.org</code>, or <code>*</code> for any. None: no browser may.'));
		o.placeholder = 'https://wallet.example.org';
		o.validate = function(section_id, value) {
			if (!value || value === '*' || /^https?:\/\/[^\s/]+$/.test(value))
				return true;
			return _('An origin such as https://wallet.example.org, or *.');
		};

		// Limits
		o = s.taboption('limits', form.Value, 'rate_limit', _('Requests a minute per client'),
			_('From one client (an IPv4 address, or an IPv6 /64). 0 is no limit.'));
		o.datatype = 'uinteger';
		o.placeholder = '300';

		o = s.taboption('limits', form.Value, 'strict_rate_limit', _('Costly requests a minute per client'),
			_('Account creation, imports, sending a transaction and asking for decoys. 0 is no limit.'));
		o.datatype = 'uinteger';
		o.placeholder = '12';

		o = s.taboption('limits', form.Value, 'max_new_accounts_per_hour', _('New accounts an hour'),
			_('New accounts and import requests an hour, across all clients. 0 is no limit.'));
		o.datatype = 'uinteger';
		o.placeholder = '1000';

		o = s.taboption('limits', form.Value, 'max_pending_requests', _('Requests held at most'),
			_('Create and import requests waiting for your word, at most.'));
		o.datatype = 'uinteger';
		o.placeholder = '10000';

		o = s.taboption('limits', form.Value, 'max_connections', _('Open connections'),
			_('Per listener, at most.'));
		o.datatype = 'uinteger';
		o.placeholder = '1024';

		o = s.taboption('limits', form.Value, 'max_connections_per_ip', _('Open connections per address'),
			_('A trusted proxy is exempt. 0 is no limit.'));
		o.datatype = 'uinteger';
		o.placeholder = '64';

		o = s.taboption('limits', form.Value, 'request_timeout', _('Request timeout (seconds)'),
			_('A request may take this long in all, body and answer included; its headers must arrive within 10 seconds.'));
		o.datatype = 'uinteger';
		o.placeholder = '30';

		// Scanning
		o = s.taboption('scanning', form.Value, 'catch_up_lanes', _('Catch-up lanes'),
			_('How many wallets with history (restored, imported, rescanned) are brought up to the chain at once, each in a lane of its own. 0 is one loop from the lowest block any wallet stands at. On a router, 1.'));
		o.datatype = 'uinteger';
		o.placeholder = '1';

		o = s.taboption('scanning', form.ListValue, 'catch_up_join', _('A queued wallet'),
			_('Whether a wallet waiting for a lane joins a running one whose cursor is below its start block, or waits for a lane of its own.'));
		o.value('follow', _('Joins a running lane'));
		o.value('wait', _('Waits for its own'));
		o.default = 'follow';

		o = s.taboption('scanning', form.Value, 'catch_up_blocks', _('Blocks per request'),
			_('Blocks a catch-up lane asks the node for at a time, 1 to 1000. Fewer takes less memory.'));
		o.datatype = 'range(1,1000)';
		o.placeholder = '100';

		o = s.taboption('scanning', form.Value, 'catch_up_in_flight', _('Requests in flight'),
			_('Catch-up requests to the node at once; the live lane’s never wait for them.'));
		o.datatype = 'range(1,64)';
		o.placeholder = '2';

		o = s.taboption('scanning', form.Value, 'gpu_arenas', _('GPU arenas'),
			_('About 43 MB of GPU memory each: one for the live lane, the rest shared by the catch-up lanes. Only with a Vulkan GPU, which a router doesn’t have: the CPU scans instead.'));
		o.datatype = 'uinteger';
		o.placeholder = _('lanes + 1');

		o = s.taboption('scanning', form.Value, 'gpu_memory_mb', _('GPU memory cap (MB)'),
			_('A cap instead of a count: at most MB / 43 arenas, at least 1.'));
		o.datatype = 'uinteger';

		return m.render();
	},

	// Save, commit, then restart the server on the new settings through
	// the page's backend.
	handleSaveApply: function(ev) {
		return this.handleSave(ev).then(function() {
			return commitThenReload();
		}).catch(function(e) {
			showError(_('Couldn’t save'), e);
		});
	}
});
