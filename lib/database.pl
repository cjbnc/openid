#!/usr/bin/perl
#
# Database Utilities
# Copyright (C) 2009
# Packetizer, Inc.
# 
# The routines utilize a global database handle called $main::dbh,
# establishes a connection to the database, and disconnects from the database.
# The database name, password, etc., must be defined elsewhere.
#

use strict;

use DBI;
use Time::HiRes;

$main::dbh = undef;

#
# DatabaseConnect
#
# Attempted to connect to the database.
#
# Parameters: None
# Returns: 1 = success, 0 = fail
#
sub DatabaseConnect
{
    my $success = 0;
    my $retries = 3;

    do
    {
        # Try to connect to the database
        if (not $main::dbh)
        {
            $main::dbh = DBI->connect("DBI:mysql:$main::database_name:$main::database_server",
                                      "$main::database_user_id",
                                      "$main::database_password",
                                      { mysql_enable_utf8 => 1,
                                        AutoCommit => 1,
                                        PrintError => 0 });

            if ($main::dbh)
            {
                $success = 1;
            }
            else
            {
                # Connect attempt failed, so sleep for 250ms
                Time::HiRes::usleep(250000);
                $retries--;
            }
        }
        else
        {
            $success = 1;
        }
    }
    while(($retries > 0) && (!$success));

    return $success;
}

#
# DatabaseDisconnect
#
# Attempted to disconnect from the database.
#
# Parameters: None
# Returns: 1 = success, 0 = fail
#
sub DatabaseDisconnect
{
    # We only need to attempt to disconnect if dbh is defined
    if (defined $main::dbh)
    {
        $main::dbh->disconnect;
        # If disconnect fails...
        # print("Error disconnecting from database: " .
        #       $main::dbh->errstr . "\n");
        $main::dbh = undef;
    }

    # For now, we will always indicate success.
    # (What would we do if it failed?)
    return 1;
}

1;
