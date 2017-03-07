var md5 = require("js-md5");
var aes = require("aes256");

// Ticket lifetime (in milliseconds)
const LIFETIME = 60 * 60 * 1000;

// Hexadecimal symbols (0..9A..F)
const MAX_HEX_SYMBOL = 0xF;
const MIN_HEX_SYMBOL = 0x0;

// Server's private key for encryption
let _secret = generateRandomString(256);

/**
 * Generates new ticket based on passed user data	
 *
 * @param {JSON object} data - user's credentials
 * @param {JSON object} options - additional options
 * @return {string} Encrypted ticket
 */
exports.generate = function(data, options = {}) {
	if (!data) return false;

	// just string of neccessary user's data and it's AES encryption
	let dataJson = JSON.stringify(data);
	let encryption = aes.encrypt(_secret, dataJson);

	// date of ticket's expiration: default is 1 hour
	let expiration = new Date( (new Date()).getTime() + LIFETIME );

	// salt for hash: 6 hex symbols
	let salt = generateRandomString(6);

	// signature
	let sign = salt + md5(`${salt} : ${_secret}`);

	// ticket's data is in the form of JSON object: {Data; Expiration date; Signature}
	var ticket = {
		data: encryption,
		expiration: expiration,
		signature: sign
	};

	return ticket;
};


/**
 * Generates string, each symbol of that is either number or A..F
 *
 * @param {number} length - length of string to be generated
 * @return {string} Random string of the required length
 */
function generateRandomString(length) {
	let s = "";
	let i = length;
	while (length-- > 0) {
		let c = Math.floor(Math.random() * (MAX_HEX_SYMBOL - MIN_HEX_SYMBOL + 1)) + MIN_HEX_SYMBOL;
		c = c.toString(16).toLowerCase();
		s += c;
	}
	return s;
};