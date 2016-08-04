var fs = require('fs');
var path = require('path');
var crypto = require('crypto');


function getKnownHosts(knownHostFile) {

	if (!knownHostFile) {
		var HOME = process.env.HOME || process.env.USERPROFILE;
		knownHostFile = path.join(HOME, '.ssh', 'known_hosts');
	}

	var md5 = function(host) {
		return crypto.createHash('md5').update(host, 'base64').digest('hex');
	};

	var data = fs.existsSync(knownHostFile) ? fs.readFileSync(knownHostFile, 'utf-8').trim().split('\n') : [];
	var entries = [];

	data.forEach(function(entry) {

		var i = entry.indexOf(' ');
		if (i === -1) return;

		var hosts = entry.slice(0, i).trim().split(',');
		var key = entry.slice(i+1);
		var fingerprint = md5(key.split(' ').pop());
		var type = key.split(' ')[0];

		hosts.forEach(function(host) {

			entries.push({
				host: host,
				publicKey: key,
				fingerprint: fingerprint,
				type: type
			});
		});
	});

	return entries;

}
module.exports = { getKnownHosts : getKnownHosts };