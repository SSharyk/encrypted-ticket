var md5 = require("js-md5");
var aes = require("aes256");

// Ticket lifetime (in milliseconds)
const LIFETIME = 60 * 60 * 1000;
const DEFAULT_EXPIRATION = 1;
const DEFAULT_TIME_ZONE = 4;

// Hexadecimal symbols (0..9A..F)
const MAX_HEX_SYMBOL = 0xF;
const MIN_HEX_SYMBOL = 0x0;

// Server's private key for encryption
const KEY_LENGTH = 256;
let _secret = generateRandomString(KEY_LENGTH);

const HASH_LENGTH = 32;
const SALT_LENGTH = 6;

/**
 * Generates new ticket based on passed user data	
 *
 * @param {JSON object} data - user's credentials
 * @param {JSON object} options - additional options
 * @return {string} Encrypted ticket
 */
exports.generate = function(data, options = {}) {
	if (!data) return false;

	// date of ticket's expiration: default is 1 hour
	let hours = (options["expiration"] != undefined) ? options["expiration"] : DEFAULT_EXPIRATION;
	hours += (options["timezone"] != undefined) ? options["timezone"] : DEFAULT_TIME_ZONE;
	let expiration = new Date( (new Date()).getTime() + LIFETIME * hours);

	// salt for hash: 6 hex symbols
	let salt = generateRandomString(SALT_LENGTH);

	// signature
	let sign = salt + md5(`${salt} : ${expiration} : ${_secret}`);

	// ticket's data is in the form of JSON object: {Data; Expiration date; Signature}
	var ticket = {
		expiration: expiration,
		signature: sign
	};
	if (options["store"]) {
		ticket["data"] = aes.encrypt(_secret, JSON.stringify(data));
	}
	
	return ticket;
};


/**
 * State of the ticket:
 * 		Valid: correct and could be used
 *		Expired: expiration date is less than Now
 *		Invalid: Digital signature is not correct
 */
exports.TicketState_Valid = TicketState_Valid = 0;
exports.TicketState_Expired = TicketState_Expired = 1;
exports.TicketState_Invalid = TicketState_Invalid = 2;

/**
 * Getting validation state of the ticket
 * 
 * @param {JSON Object} ticket - ticket need be validated
 * @return {TicketState} Current state of the ticket (Valid/invalid/expired/...)
 */
exports.getTicketState = function(ticket) {
	// Check if expiration date is passed
	if (ticket["expiration"] != undefined && ticket["expiration"] < new Date()) 
		return TicketState_Expired;

	// Check the digital signature
	let signTicket = ticket["signature"];
	if (signTicket == undefined) 
		return TicketState_Invalid;

	let saltLength = signTicket.length - HASH_LENGTH;
	let salt = signTicket.substr(0, saltLength);
	let sign = salt + md5(`${salt} : ${ticket["expiration"]} : ${_secret}`);
	return (signTicket == sign) ? TicketState_Valid : TicketState_Invalid;
};


/**
 * Checks if the ticket is valid (i.e., signature is correct and it is not expired)
 * 
 * @param {JSON Object} ticket - ticket need be validated
 * @return {boolean} True if the ticket is correct; otherwise return false
 */
 exports.isValid = function(ticket) {
 	return this.getTicketState(ticket) == TicketState_Valid;
 }


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

/**
 * Extracts data from emcrypted ticket
 *
 * @param {JSON Object} ticket - ticket need be decrypted
 * @return {JSON Object} Encrypted data and Expiration date of the ticket as a JSON
 */
exports.decryptData = function(ticket) {
	if (ticket["data"] == undefined)
		throw new ReferenceError("No encrypted data in the ticket");

	return aes.decrypt(_secret, ticket["data"]);
}

/**
 * Clears ticket by setting its expiration date to zero
 * @param {JSON Object} ticket - ticket need be deleted
 */ 
exports.delete = function(ticket) {
	if (!this.isValid(ticket))
		throw new Error('Ticket is not valid');

	ticket["expiration"] = new Date(0);
	
	if (ticket["data"]) 
		delete ticket["data"];
	
	let salt = generateRandomString(SALT_LENGTH);
	ticket["signature"] = salt + md5(`${salt} : ${ticket["expiration"]} : ${_secret}`);
}