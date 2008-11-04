# keychain_access

The idea behind keychain_access is to provide Keychain features to the command
line.  Apples security(1) command already does some of this.

Unfortunately there is no convenient way to to access public/private key pairs
stored in the Keychain over security(1).  This is why I wrote keychain_access,
I wanted to use private keys stored in my keychain in command line scripts.


## Installing

Type <code>make</code> and then copy the executable named "keychain_access" to wherever you like.


## Author

Torsten Becker <torsten.becker@gmail.com>
