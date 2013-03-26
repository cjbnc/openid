#!/usr/bin/perl
#
# OpenID Common Functions
# Copyright (C) 2009, 2010
# Packetizer, Inc.
#

use strict;

use NCSUaklib;
use SysNews::UserInfo;
use URI::Escape;

#
# CreateAssociation
# 
# This routine will create an association using the specified association
# type.  It will return the association handle (or zero if an error)
# along with the mac_key.  It is assumed that a database connection
# is already established.
#
sub CreateAssociation
{
    my ($assoc_type,$session_type) = @_;

    my ($sth,
        $mac_key,
        $assoc_handle);

    # Generate a mac_key for this association
    if ($assoc_type eq "HMAC-SHA256")
    {
        # 256-bit random number (HMAC-SHA256)
        $mac_key = makerandom_octet( Length=>32, Strength => 1);
    }
    else
    {
        # 160-bit random number (HMAC-SHA256)
        $mac_key = makerandom_octet( Length=>20, Strength => 1);
    }

    $sth = $main::dbh->prepare("INSERT INTO openid_assoc(serial,assoc_type,session_type,mac_key,timestamp) VALUES (?,?,?,?,?)");
    if (!$sth)
    {

        return (0,undef);
    }

    if (!$sth->execute( 0,
                        $assoc_type,
                        $session_type,
                        encode_base64($mac_key,''),
                        time()))
    {
        return (0, undef);
    }

    # Grab the serial row to use as the association handle
    $assoc_handle = $sth->{'mysql_insertid'};

    return ($assoc_handle, $mac_key);
}

#
# GetAssociation
#
# This routine will get an association (i.e., return the mac_key) for a
# given assoc_handle.  The routine will return the assoc_handle,
# association type (HMAC algorithm) and the mac_key as return parameters.
# If the assoc_handle could not be found or has expired, then the routine
# will return (0, undef, undef).
#
sub GetAssociation
{
    my ($assoc_handle) = @_;

    my ($sth,
        $assoc_type,
        $mac_key,
        $valid_time);

    $sth = $main::dbh->prepare("SELECT serial, assoc_type, mac_key FROM openid_assoc WHERE serial = ? AND timestamp > ?");
    if (!$sth)
    {
        return (0, undef, undef);
    }

    # How long is an association valid?
    $valid_time = time() - ($main::assoc_expiration +
                            $main::assoc_expiration_grace);

    if (!$sth->execute($assoc_handle,$valid_time))
    {
        return (0, undef, undef);
    }

    # Prepare for the worst...
    $assoc_handle = 0;
    $mac_key = undef;

    # If there is a single row, fetch it
    if ($sth->rows == 1)
    {
        ($assoc_handle, $assoc_type, $mac_key) = $sth->fetchrow_array;
    }

    $sth->finish;

    return ($assoc_handle, $assoc_type, decode_base64($mac_key));
}

#
# RecordSignature
#
# This function will insert a row into the database to record a signature.
# It returns 1 if successful and 0 if it fails.
#
sub RecordSignature
{
    my ($assoc_handle, $nonce, $signed, $signature, $identity, $realm) = @_;

    my ($sth);

    $sth = $main::dbh->prepare("INSERT INTO openid_sigs(serial, assoc_handle, nonce, signed, signature, identity, realm, timestamp, stat) values (?,?,?,?,?,?,?,?,'A')");

    if ((!$sth) ||
        (!$sth->execute(0,
                        $assoc_handle,
                        $nonce,
                        $signed,
                        $signature,
                        $identity,
                        $realm,
                        time())))
    {
        return 0;
    }

    return 1;
}

#
# VerifySignature
# 
# This function will verify that a signature exists, matching all of the
# parameters passed into this function.  Note it does not verify all
# of the openid.* signature elements, since they may or may not
# match.  As an example, openid.return_to does not match in some
# production systems, contrary to what Section 11.4.2.1 of the OpenID 2.0
# specification says.  It returns 1 if the signature was verified and
# 0 if it was not verified.
#
sub VerifySignature
{
    my ($assoc_handle, $nonce, $signed, $signature, $identity) = @_;

    my ($sth,
        $serial,
        $result);

    $sth = $main::dbh->prepare("SELECT serial FROM openid_sigs WHERE assoc_handle = ? AND nonce = ? AND signed = ? AND signature = ? AND identity = ? AND stat = 'A'");

    if ((!$sth) ||
        (!$sth->execute($assoc_handle,
                        $nonce,
                        $signed,
                        $signature,
                        $identity)))
    {
        return 0;
    }

    # There should be a single matching row
    if ($sth->rows == 1)
    {
        $result = 1;
        ($serial) = $sth->fetchrow_array;

        # Mark the signature entry as verified to prevent replay attacks
        $main::dbh->do("UPDATE openid_sigs SET stat = 'V' WHERE serial = $serial");
    }
    else
    {
        $result = 0;
    }

    $sth->finish;

    return $result;
}

#
# ValidSHAPassword
#
# This routine will validate the user's password, returning the serial
# number of the associated user record, or 0 if the password is invalid.
#
# This function is replaced by our NCSU version.
#
sub ValidSHAPassword
{
    my ($username, $password) = @_;

    my ($sth,
        $serial);

    # Hash the provided password
    $password = sha1_hex($password);

    # Try to find a matching row
    $sth = $main::dbh->prepare("SELECT serial FROM openid_users WHERE username = ? AND password = ?");
    if (($sth) &&
        ($sth->execute($username, $password)))
    {
        if ($sth->rows == 1)
        {
            ($serial) = $sth->fetchrow_array;
            if ($serial > 0)
            {
                return $serial;
            }
        }
    }

    return 0;
}

sub ValidPassword
{
    my ($username, $password) = @_;

    my ($sth,
        $serial);

    # Check the userid and password via NCSUaklib
    my $error = krb5_login( $username, $password );
    krb5_destroy();

    if ($error ne 'OK')
    {
        return 0;
    }

    # Try to find a matching row
    $sth = $main::dbh->prepare("SELECT serial FROM openid_users WHERE username = ?");
    if (($sth) &&
        ($sth->execute($username)))
    {
        if ($sth->rows == 1)
        {
            ($serial) = $sth->fetchrow_array;
            if ($serial > 0)
            {
                return $serial;
            }
        }
    }

    return 0;
}

#
# GetUserKey
# 
# This routine will get or set the key in the user table, also updating the
# expiration date.
#
sub GetUserKey
{
    my (%request) = @_;

    my ($sth,
        $user_key,
        $user_key_expires,
        $serial,
        $current_time,
        $expires);

    $sth = $main::dbh->prepare("SELECT serial, user_key, key_expires FROM openid_users WHERE username = ?");
    if ($sth)
    {
        $sth->execute($request{'identity'});
        ($serial, $user_key, $user_key_expires) = $sth->fetchrow_array;
        $sth->finish;
    }

    # The rest we can do only if we have a valid serial key
    if ($serial > 0)
    {
        $current_time = time();
        $expires = $current_time + $main::openid_cookie_expiration;

        if (($user_key_expires > 0) &&
            ($user_key_expires > $current_time) &&
            (length($user_key) > 0) &&
            ($request{'openid_user_key'} eq $user_key))
        {
            # Update the expiration timestamp
            $sth = $main::dbh->prepare("UPDATE openid_users SET key_expires = ? WHERE serial = ?");
            $sth->execute($expires, $serial);
        }
        else
        {
            # Get a new user key value
            $user_key = GetNonce();
            for(my $i=0; $i<100; $i++)
            {
                $user_key .= int(rand(4294967296));
            }
            $user_key = sha1_hex($user_key);
            $sth = $main::dbh->prepare("UPDATE openid_users SET user_key = ?, key_expires = ? WHERE serial = ?");
            $sth->execute($user_key, $expires, $serial);
        }
    }

    return ($user_key);
}

#
# DeleteUserKey
# 
# This routine will delete the key in the user table
#
sub DeleteUserKey
{
    my (%request) = @_;

    my ($sth,
        $user_key,
        $user_key_expires,
        $serial,
        $current_time,
        $expires);

    $sth = $main::dbh->prepare("SELECT serial FROM openid_users WHERE username = ?");
    if ($sth)
    {
        $sth->execute($request{'identity'});
        ($serial) = $sth->fetchrow_array;
        $sth->finish;
    }

    # The rest we can do only if we have a valid serial key
    if ($serial > 0)
    {
        # Update the expiration timestamp
        $sth = $main::dbh->prepare("UPDATE openid_users SET user_key = \"\", key_expires = 0 WHERE serial = ?");
        $sth->execute($serial);
    }
}


#
# RecognizedUser
#
# This routine will return a 1 if the user is recognized or 0 if the
# user is not recognized.  By "recognized", we mean that we know that
# the user has a valid association with the requesting entity.
# 
sub RecognizedUser
{
    my (%request) = @_;

    my ($sth,
        $user_key,
        $serial,
        $current_time);

    # If it appears that we recognize the user, then grab the user key from the
    # database and compare that to what we received from the browser.
    if ((length($request{'identity'}) > 0) &&
        (length($request{'openid_user_key'}) > 0))
    {
        $sth = $main::dbh->prepare("SELECT serial, user_key FROM openid_users WHERE username = ? AND key_expires > ?");
        $current_time = time();
        $sth->execute($request{'identity'},$current_time);
        ($serial, $user_key) = $sth->fetchrow_array;
        $sth->finish;
        if ($request{"openid_user_key"} eq $user_key)
        {
            return 1;
        }
    }

    return 0;
}

#
# SignalSetupNeeded
#
# Perform necessary signaling to indicate that a setup is needed.
#
sub SignalSetupNeeded
{
    my (%request) = @_;
    my ($openid_ns,
        $setup_url,
        $location);

    $openid_ns = uri_escape($main::openid_ns);
    $setup_url = uri_escape($main::openid_setup_url);

    # Are there parameters in the URL?
    if ($request{'return_to'} =~ /\?/)
    {
        $location = $request{'return_to'} . "&";
    }
    else
    {
        $location = $request{'return_to'} . "?";
    }

    if ($request{'ns'} eq $main::openid_ns_1_1)
    {
        $location .= "openid.ns=$openid_ns&openid.mode=id_res";
        $location .= "&openid.user_setup_url=$setup_url";
    }
    else
    {
        $location .= "openid.ns=$openid_ns&openid.mode=setup_needed";
    }

    print "Location: $location\r\n";
    print "\r\n";
}

#
# MakeHTMLSafe
#
# Make the given string safe for display in an HTML document.  The string
# must be passed by reference.
#
sub MakeHTMLSafe
{
    my ($text_line) = @_;

    $$text_line =~ s/&/&amp;/g;
    $$text_line =~ s/</&lt;/g;
    $$text_line =~ s/>/&gt;/g;
    $$text_line =~ s/"/&quot;/g;
}

#
# GetUser
#
# This routine will get the user information from the database.
# It will return a HTTP status code indicating the result.
#
sub GetUser
{
    my ($username) = @_;

    my ($sth,
        $name,
        $homepage);

    $sth = $main::dbh->prepare("SELECT name, homepage FROM openid_users WHERE username = ?");
    if (!$sth)
    {
        return (500, "", "");
    }

    if (!$sth->execute($username) || ($sth->rows != 1))
    {
        # Finish the failed SQL statement
        $sth->finish;

        # if the user does not exist, try to import them from UserInfo
        my $ui = SysNews::UserInfo->new($username);
        if (!defined $ui->{username}) 
        {
            return (404, "", "");
        }

        $username = $ui->{username};
        $name = $ui->{fullname};
        $homepage = undef;
        my $pass = 'ncsu';

        $sth = $main::dbh->prepare("INSERT INTO openid_users (username, password, name, homepage) VALUES (?, ?, ?, ?)");
        if (!$sth)
        {
            return (500, "", "");
        }

        if (!$sth->execute($username, $pass, $name, $homepage))
        {
            return (500, "", "");
        }

        # Finish the SQL statement
        $sth->finish;

        return (200, $name, $homepage);
    }

    # user does exist, process normally
    ($name, $homepage) = $sth->fetchrow_array;

    # Finish the SQL statement
    $sth->finish;

    return (200, $name, $homepage);
}

#
# ShowNotFoundPage
#
sub ShowNotFoundPage
{
    my ($request_uri) = uri_unescape($ENV{'REQUEST_URI'});

    MakeHTMLSafe(\$request_uri);

    print "Status: 404 Not Found\r\n";
    print "Content-Type: text/html; charset=UTF-8\r\n";
    print "\r\n";


    if (!open(TEMPLATE, "<:encoding(UTF-8)", "$main::openid_not_found_template"))
    {
        return;
    }

    while(<TEMPLATE>)
    {
        s/<!--#echo var="REQUEST_URI" -->/$request_uri/;
        print;
    }

    close(TEMPLATE);
}

1;
