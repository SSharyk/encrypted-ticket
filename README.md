# encrypted-ticket
Encrypted ticket Node.js package
Custom ticket generation and validation util

## Summary
_Version_: 0.1.2

_Usage_: authorization cases

## Description
Ticket is a data structure used to authorize and/or authenticate the user. It represents JSON Object with three fields:
* Expiration date (1 hour as default)
* Signature (used for validating)
* User's data: encrypted with AES algo (optional; default is `false`)


## How to use
##### Commands
1. To install the package, type `npm install encrypted-ticket` in prompt.
2. Use `require('encrypted-ticket')` to import the functionality.
3. Use `ticket.generate(data, option)` to create new ticket. `Data` is user's data need to be stored in the ticket and used in next session request, and `option` is set of additional values used to specify tickets generation process options.
Option could be:
* `store` : `true` if encrypted data need be stored inside the ticket
* `expiration` : time period that sets ticket's expiration period (in hours; default is `1`)
* `timezone` : number that sets local and UTC time difference (in hours; default is `4`)
4. Use `ticket.isValid(t)` to check if the ticket `t` is valid (i.e., it's signature is correct and expiration date is not passed yet).
5. Use `ticket.decryptData(t)` to decrypt data in the according field.

##### Full example
###### **Generation**
```
// Import 
var ticket = require('encrypted-ticket');

// Create new ticket (with hard-coded values)
var user = {
	id: "abcdefghijklmnop",
	login: "admin",
	password: "5f4dcc3b5aa765d61d8327deb882cf99"
};
var options = {
	store: true
};
var t = ticket.generate(user, options);
```
Resuly is (for example, depends on secret server's key for encryption and hashing):
```
{ 
  expiration: 2017-03-08T18:39:53.767Z,
  signature: 'b55a3087a15a62eea0f0da017ba94048ab7dc0',
  data: 'AHQfUrXbDl9LQ2eeowAoaJiOp828PFvIiBWvwQpwEaBAWF49x3RR8bMi2Ak1jvG8mi4vTfJsEmP8twc1ekI3kkY9pRGB9cGX16MEk0chjzsGHeKuexZC+Qw7fSBiv/Ah/mloyYm92Q==' 
}
```

###### **Validation**
```
if (ticket.isValid(t)) {
  console.log(ticket.decryptData(t));
}
```
Or another way to do the same validation:
```
if (ticket.getTicketState(t) == ticket.TicketState_Valid) {
  console.log(ticket.decryptData(t));
}
```
Result (for previous example):
```
{"id":"abcdefghijklmnop","login":"admin","password":"5f4dcc3b5aa765d61d8327deb882cf99"}
```
