package memcached

// https://github.com/memcached/memcached/blob/master/doc/protocol.txt
// https://www.zybuluo.com/phper/note/443547
/*
Authentication
--------------
Optional username/password token authentication (see -Y option). Used by
sending a fake "set" command with any key:

set <key> <flags> <exptime> <bytes>\r\n
username password\r\n

key, flags, and exptime are ignored for authentication. Bytes is the length
of the username/password payload.

- "STORED\r\n" indicates success. After this point any command should work
  normally.

- "CLIENT_ERROR [message]\r\n" will be returned if authentication fails for
  any reason.

*/
func Check(Host, Username, Password string, Port int) (bool, error) {
	return false, nil
}
