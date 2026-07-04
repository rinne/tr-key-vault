'use strict';

const ou = require('optist/util');

function dbOpts(NAME) {

	return [
		{ longName: 'db-host',
		  description: 'PostgreSQL server host or address',
		  hasArg: true,
		  environment: NAME + '_OPT_PG_HOST',
		  defaultValue: '127.0.0.1' },
		{ longName: 'db-port',
		  description: 'PostgreSQL server port',
		  hasArg: true,
		  environment: NAME + '_OPT_PG_PORT',
		  defaultValue: '5432',
		  optArgCb: ou.integerWithLimitsCbFactory(1, 65535) },
		{ longName: 'db-max-connections',
		  description: 'Maximum number of concurrent DB connections',
		  hasArg: true,
		  environment: NAME + '_OPT_PG_MAX_CONNECTIONS',
		  defaultValue: '32',
		  optArgCb: ou.integerWithLimitsCbFactory(1, 1000) },
		{ longName: 'db-tls',
		  environment: NAME + '_OPT_PG_TLS',
		  description: 'Uses TLS for DB connections' },
		{ longName: 'db-user',
		  description: 'Database user name',
		  hasArg: true,
		  optArgCb: function(s) { return (!!s) ? s : null; },
		  environment: NAME + '_OPT_PG_USER' },
		{ longName: 'db-password',
		  description: 'Database password',
		  requiresAlso: [ 'db-user' ],
		  hasArg: true,
		  optArgCb: function(s) { return (!!s) ? s : null; },
		  environment: NAME + '_OPT_PG_PASSWORD' },
		{ longName: 'db-database',
		  description: 'Database database name',
		  hasArg: true,
		  environment: NAME + '_OPT_PG_DATABASE',
		  defaultValue: 'data' }
	];

}

module.exports = dbOpts;
