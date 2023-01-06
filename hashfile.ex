--
-- hashfile.ex - Specify one or more hash flags and one or more file names.
--
-- $ eui hashfile.ex -sha256 freehash.h freehash.c freehash.e
-- f57be16cc28d6c7d852c08a023b81542cec1d2f7bd75efc1d403045001fa53aa *freehash.h
-- fc540e5e8f68c92df73d571580511e02fee2b1ebd440024a50faec370ea9cafc *freehash.c
-- b5fba03f777f647fe127c0e6bb33a25ce2e69ea48fc49e7a40a44db6280ae1c2 *freehash.e
--

include freehash.e

function hash_to_string( integer id, sequence file )
-- hash a file and print the bytes to hex string

	sequence str = ""
	sequence bytes = hash_file( id, file )

	for i = 1 to length( bytes ) do
		str &= sprintf( "%02x", bytes[i] )
	end for

	return str + ('A' <= str and str <= 'F') * ('a' - 'A')
end function 

procedure main()

	sequence cmd = command_line()
	sequence files = {}, hashes = {}

	for i = 3 to length( cmd ) do
		if cmd[i][1] != '-' then
			files = append( files, cmd[i] )
		else
			integer id = find_hash( cmd[i][2..$] )
			if id = -1 then
				printf( 2, "hash \"%s\" not found\n", {cmd[i]} )
				abort( 1 )
			end if
			hashes = append( hashes, id )
		end if
	end for

	for i = 1 to length( files ) do
		for j = 1 to length( hashes ) do
			sequence string = hash_to_string( hashes[j], files[i] )
			printf( 1, "%s *%s\n", {string,files[i]} )
		end for
	end for

end procedure

main()
