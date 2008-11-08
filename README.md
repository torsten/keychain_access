# keychain_access

The idea behind keychain_access is to provide Keychain features in the command line.  Apples security(1) command does already some work for this. Unfortunately there is no convenient way to to access public/private key pairs stored in the Keychain via security(1).

This is why I wrote keychain_access.  I wanted to use private keys stored in my keychain in command line scripts.  This is helpful for signing builds for
Sparkle without having to type my password all the time.  But at the same time you do not have to worry that your private keys are stored in plaintext on your harddrive.


## Usage

WIP


## Installing

Type <code>make</code> and then copy the executable named "keychain_access" to wherever you like in your $PATH.


## License

MIT.


## Author

Torsten Becker &lt;torsten dot becker at gmail dot com>
