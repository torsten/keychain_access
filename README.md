# keychain_access

The idea behind keychain_access is to provide Keychain features in the command line.  Apples security(1) command does already some work for this. Unfortunately there is no convenient way to to access public/private key pairs stored in the Keychain via security(1).

This is why I wrote keychain_access.  I wanted to use private keys stored in my keychain in command line scripts.  This is helpful for signing builds for
Sparkle without having to type my password all the time.  But at the same time you do not have to worry that your private keys are stored in plaintext on your harddrive.


## Usage

<pre>
$ keychain_access -h
Usage: keychain_access [-vh] [-p &lt;password>] &lt;key_name>
Options:
  -p &lt;password>   Encrypt exported private keys with &lt;password>.
                  The default is to export them without a password.
  -h              Show this information.
  -v              Print current version number.
  &lt;key_name>      The name of the keychain item you want to access.
                  Has to be a public or private key.
</pre>

If you want to pass a key from the Keychain to an openssl command without the key touching the harddrive, use a named pipe.  This is how I use keychain_access to sign [Sparkle](http://sparkle.andymatuschak.org/) updates:

<pre>
PIPE=$OUTPUT_DIR/key.pipe
mkfifo -m 0600 $PIPE
keychain_access a.unique.name.for.the.private.key > $PIPE &amp;

SIG=`openssl dgst -sha1 -binary &lt; "$OUTPUT_DIR/$VOL.dmg" | openssl dgst -dss1 -sign "$PIPE" | openssl enc -base64`

rm $PIPE
</pre>


## Installing

Type <code>make</code> and then copy the executable named "keychain_access" to wherever you like in your $PATH.


## License

MIT, see keychain_access.c.


## Author

Torsten Becker &lt;torsten dot becker at gmail dot com>
