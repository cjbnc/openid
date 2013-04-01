#
# nonce.pl
# Copyright (C) 2009
# Packetizer, Inc.
#
# This file contains library routines to generate a nonce and to
# then validate and remove a nonce.
#
# Note: It is assumed that there is already an established database
#       connection.  These routines will not attempt to establish
#       a database connection.
#

use MIME::Base64;

#
# GetNonce
#
# This routine will produce and return a nonce value.  In the case of
# a database error, an empty string will be returned.
#
sub GetNonce {
    my ( $serial, $random, $current_time );

    if ( !$main::dbh ) {
        return "";
    }

    # Assign values for insertion into the nonce table
    $serial       = 0;
    $random       = int( rand(4294967296) );
    $current_time = time();

    if (!$main::dbh->do(
            "INSERT INTO `nonce` (`serial`, `random`, `timestamp`) VALUES ($serial, $random, $current_time)"
        )
        )
    {
        return "";
    }

    # Get the serial number from the MySQL driver
    $serial = $main::dbh->{'mysql_insertid'};

    # Create the Base64-encoded nonce
    #  Note that the prepended '1' is a "generation" (version) indicator
    return encode_base64( "1:$serial:$random:$current_time", "" );
}

#
# ValidateNonce
#
# This routine will validate a given nonce, verifying that it exits
# and removing it in the process.  It will return 1 if valid or 0 if
# invalid or if there was an error.
#
sub ValidateNonce {
    my ($nonce) = @_;

    my ( $nonce_time, $serial, $random, $sth, $generation );

    if ( length($nonce) == 0 ) {
        return 0;
    }

    # Get the nonce components
    ( $generation, $serial, $random, $nonce_time )
        = split( ':', decode_base64($nonce) );

    # Do some basic checks against the nonce
    if (   ( $generation != 1 )
        || ( length($serial) == 0 )
        || ( $serial == 0 )
        || ( length($random) == 0 ) )
    {
        return 0;
    }

    # We will attempt to delete the nonce, which should only be possible
    # if all of the nonce components were provided properly.
    $sth
        = $main::dbh->prepare(
        "DELETE FROM nonce WHERE serial = ? AND random = ? AND timestamp = ?"
        );

    if ( not $sth ) {
        return 0;
    }

    if ( !$sth->execute( $serial, $random, $nonce_time ) ) {
        return 0;
    }

    # There should be one and only one matching row
    if ( $sth->rows != 1 ) {
        return 0;
    }

    return 1;
}

1;
