#!/usr/bin/perl
#
# checkid
# Copyright (C) 2009, 2010, 2011
# Packetizer, Inc.
#
# This script performs the background processing for the OpenID
# authentication request.  Since this script receives the user's
# password and provides cookies that associate the user, it is
# strongly recommended that this script be executed only over HTTPS.
#

use strict;

use CGI;
use URI::Escape;
use Digest::SHA qw( sha1_hex hmac_sha256 hmac_sha1 );
use Crypt::DH;
use Crypt::Random qw( makerandom_octet );
use Math::BigInt lib => 'GMP';
use POSIX qw(strftime);

require "config.pl";
require "database.pl";
require "nonce.pl";
require "openid_config.pl";
require "openid.pl";

#
# ForceCheckIDSetup
#
# The user's password did not validate, so force the browser back to
# the login page
#
sub ForceCheckIDSetup
{
    my (%request) = @_;

    my ($location);

    $location = $main::op_endpoint;
    if ($location =~ /\?/)
    {
        $location .= "&";
    }
    else
    {
        $location .= "?";
    }

    $location .= "openid.ns=" . uri_escape($main::openid_ns);
    $location .= "&openid.mode=checkid_setup";
    $location .= "&openid.return_to=" . uri_escape($request{'return_to'});
    $location .= "&openid.identity=" . uri_escape($main::openid_url_prefix . $request{'identity'});
    $location .= "&openid.claimed_id=" . uri_escape($main::openid_url_prefix . $request{'identity'});

    $location .= "&openid.assoc_handle=" . uri_escape($request{'assoc_handle'});
    if ($request{'ns'} eq $main::openid_ns_1_1)
    {
        $location .= "&openid.trust_root=" . uri_escape($request{'realm'});
    }
    else
    {
        $location .= "&openid.realm=" . uri_escape($request{'realm'});
    }
    $location .= "&packetizer.message=" . uri_escape("Incorrect password.");

    # Invalidate the user's credentials since they apparently did not validate
    # and specify an expiration date for the cookies so that they will be
    # removed from the browser's cache.
    my ($expires) = strftime( "%a, %e-%b-%Y %H:%M:%S GMT", gmtime(0));
    if ((length($main::openid_secure_cookie_domain) > 0) &&
        (length($main::openid_insecure_cookie_domain) > 0))
    {
        print "Set-Cookie: openid_user=; " .
              "Domain=$main::openid_insecure_cookie_domain; " .
              "Path=/; Expires=$expires\r\n";
        print "Set-Cookie: openid_user_key=; " .
              "Domain=$main::openid_secure_cookie_domain; " .
              "Path=/; Expires=$expires; Secure\r\n";
    }
    print "Location: $location\r\n";
    print "\r\n";
}

#
# ReturnNegativeResponse
#
sub ReturnNegativeResponse
{
    my ($error_string, %request) = @_;

    my ($openid_ns,
        $contact,
        $location);

    $openid_ns = uri_escape($main::openid_ns);
    $contact = uri_escape($main::contact);
    $error_string = uri_escape($error_string);

    if ($request{'return_to'} =~ /\?/)
    {
        $location = $request{'return_to'} . "&";
    }
    else
    {
        $location = $request{'return_to'} . "?";
    }
    $location .= "openid.ns=$openid_ns&openid.mode=error" .
                 "&openid.error=$error_string&openid.contact=$contact";

    print "Location: $location\r\n";
    print "\r\n";
}

#
# CancelRequest
#
# A "cancel" is sent to the remote server if the user cancels the login
# process or if the password cannot be authenticated.
#
sub CancelRequest
{
    my (%request) = @_;

    my ($openid_ns,
        $contact,
        $location);

    $openid_ns = uri_escape($main::openid_ns);

    if ($request{'return_to'} =~ /\?/)
    {
        $location = $request{'return_to'} . "&";
    }
    else
    {
        $location = $request{'return_to'} . "?";
    }
    $location .= "openid.ns=$openid_ns&openid.mode=cancel";

    print "Location: $location\r\n";
    print "\r\n";
}

#
# LogoffRequest
#
# This request is received from the user's identity page when the system
# detects they are logged in and they press the logoff button.
#
sub LogoffRequest
{
    my (%request) = @_;

    my ($location);

    DeleteUserKey(%request);

    $location = $request{'return_to'};

    # Invalidate the user's credentials to prevent login, setting the
    # expiration date of the cookies so that they will be removed
    my ($expires) = strftime( "%a, %e-%b-%Y %H:%M:%S GMT", gmtime(0));
    if ((length($main::openid_secure_cookie_domain) > 0) &&
        (length($main::openid_insecure_cookie_domain) > 0))
    {
        print "Set-Cookie: openid_user=; " .
              "Domain=$main::openid_insecure_cookie_domain; " .
              "Path=/; Expires=$expires\r\n";
        print "Set-Cookie: openid_user_key=; " .
              "Domain=$main::openid_secure_cookie_domain; " .
              "Path=/; Expires=$expires; Secure\r\n";
    }
    print "Location: $location\r\n";
    print "\r\n";
}


#
# MAIN
#
{
    my ($query,
        %request,
        $nonce,
        $current_time,
        $invalidate_handle,
        $url_reply,
        $assoc_type,
        $to_be_sig,
        $signature,
        $signed,
        $location,
        $mac_key);

    # Ensure that all output is proper UTF-8
    binmode(STDOUT, ":encoding(UTF-8)");

    $query = new CGI;

    # Grab all of the parameters
    foreach ($query->param)
    {
        $request{"$_"} = $query->param("$_");
    }

    # Grab the OpenID secure cookie
    $request{'openid_user_key'} = $query->cookie('openid_user_key');

    #
    # Connect to the database, and return an error if we fail
    #
    if ((length($request{'identity'}) == 0) ||
        (length($request{'return_to'}) == 0) ||
        (!DatabaseConnect()))
    {
        if (length($request{'return_to'}) == 0)
        {
            print "Location: $main::openid_url_prefix\r\n";
            print "\r\n";
        }
        else
        {
            ReturnNegativeResponse("Identity and/or password information missing.", %request);
        }
        exit 0;
    }

    # Determine the current time and produce a nonce
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime();
    $year += 1900;
    $mon++;

    $current_time = sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
                            $year, $mon, $mday, $hour, $min, $sec);
    $nonce = GetNonce();
    $nonce = "$current_time-$nonce";

    # If the user cancelled the login process or if the password does
    # not match, cancel the request.
    if ($request{'submit'} eq "Cancel")
    {
        CancelRequest(%request);
    }
    elsif ($request{'submit'} eq "Logoff")
    {
        LogoffRequest(%request);
    }
    elsif ((!RecognizedUser(%request)) &&
           (!($request{'user_id'} = ValidPassword($request{'identity'},$request{'password'}))))
    {
        if ($request{'mode'} eq "checkid_immediate")
        {
            SignalSetupNeeded(%request);
        }
        else
        {
            ForceCheckIDSetup(%request);
        }
    }
    else
    {
        # Get or create association, as necessary
        $invalidate_handle = "";
        if (length($request{'assoc_handle'}) > 0)
        {
            $invalidate_handle = $request{'assoc_handle'};
            ($request{'assoc_handle'}, $assoc_type, $mac_key) =
                        GetAssociation($request{'assoc_handle'});
            if ($request{'assoc_handle'} > 0)
            {
                $invalidate_handle = "";
            }
            else
            {
                ($request{'assoc_handle'}, $mac_key)
                                = CreateAssociation("HMAC-SHA1", "DH-SHA1");
                $assoc_type = "HMAC-SHA1";
            }
        }
        else
        {
            # If we do not have an association handle passed in, let's create
            # an association using HMAC-SHA1 and DH-SHA1 as defaults.
            ($request{'assoc_handle'}, $mac_key)
                            = CreateAssociation("HMAC-SHA1", "DH-SHA1");
            $assoc_type = "HMAC-SHA1";
        }

        if ($request{'assoc_handle'} == 0)
        {
            ReturnNegativeResponse("Error retrieving association.", %request);
        }
        else
        {
            #
            # Return a positive assertion
            #
            $url_reply = "";
            $to_be_sig = "";

            $url_reply .= "openid.ns=" . uri_escape($main::openid_ns);

            $url_reply .= "&openid.mode=id_res";

            # The 1.1 spec did not define op_endpoint, so do not use it
            if ($request{'ns'} ne $main::openid_ns_1_1)
            {
                $url_reply .= "&openid.op_endpoint=" . uri_escape($main::op_endpoint);
                $to_be_sig .= "op_endpoint:$main::op_endpoint\n";
            }

            $url_reply .= "&openid.identity=" . uri_escape($main::openid_url_prefix . $request{'identity'});
            $to_be_sig .= "identity:$main::openid_url_prefix" . $request{'identity'} . "\n";

            $url_reply .= "&openid.claimed_id=" . uri_escape($main::openid_url_prefix . $request{'identity'});
            $to_be_sig .= "claimed_id:$main::openid_url_prefix" . $request{'identity'} . "\n";

            $url_reply .= "&openid.return_to=" . uri_escape($request{'return_to'});
            $to_be_sig .= "return_to:" . $request{'return_to'} . "\n";

            $url_reply .= "&openid.assoc_handle=" . uri_escape($request{'assoc_handle'});
            $to_be_sig .= "assoc_handle:" . $request{'assoc_handle'} . "\n";

            $url_reply .= "&openid.response_nonce=" . uri_escape($nonce);
            $to_be_sig .= "response_nonce:$nonce\n";

            if (length($invalidate_handle) > 0)
            {
                $url_reply .= "&openid.invalidate_handle=" . uri_escape($invalidate_handle);
            }

            # Sign elements of the message
            if ($assoc_type eq "HMAC-SHA256")
            {
                # Sign $to_be_sig using DH-SHA256
                $signature = encode_base64(hmac_sha256($to_be_sig, $mac_key), '');
            }
            else
            {
                # Sign $to_be_sig using DH-SHA1
                $signature = encode_base64(hmac_sha1($to_be_sig, $mac_key), '');
            }

            # The 1.1 spec did not define op_endpoint, so do not use it
            if ($request{'ns'} ne $main::openid_ns_1_1)
            {
                $signed = "op_endpoint,identity,claimed_id,return_to,assoc_handle,response_nonce";
            }
            else
            {
                $signed = "identity,claimed_id,return_to,assoc_handle,response_nonce";
            }

            $url_reply .= "&openid.signed=" . uri_escape($signed);

            $url_reply .= "&openid.sig=" . uri_escape($signature);

            RecordSignature($request{'assoc_handle'},
                            $nonce,
                            $signed,
                            $signature,
                            "$main::openid_url_prefix" . $request{'identity'},
                            $request{'realm'});

            if ($request{'return_to'} =~ /\?/)
            {
                $location = $request{'return_to'} . "&$url_reply";
            }
            else
            {
                $location = $request{'return_to'} . "?$url_reply";
            }

            if (($request{'sticky'} eq "Y") &&
                (length($main::openid_secure_cookie_domain) > 0) &&
                (length($main::openid_insecure_cookie_domain) > 0))
            {
                my ($user_nonce) = GetUserKey(%request);
                my ($expires) = strftime( "%a, %e-%b-%Y %H:%M:%S GMT",
                                          gmtime(time() +
                                          $main::openid_cookie_expiration));
                print "Set-Cookie: openid_user=" . $request{'identity'} .
                      "; Domain=$main::openid_insecure_cookie_domain; " .
                      "Path=/; Expires=$expires\r\n";
                print "Set-Cookie: openid_user_key=" . $user_nonce .
                      "; Domain=$main::openid_secure_cookie_domain; " .
                      "Path=/; Expires=$expires; Secure\r\n";
            }
            print "Location: $location\r\n";
            print "\r\n";
        }
    }

    # Disconnect from the database
    DatabaseDisconnect();
}
