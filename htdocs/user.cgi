#!/usr/bin/perl
#
# user
# Copyright (C) 2009, 2010
# Packetizer, Inc.
#
# This script will generate an HTML page representing the user.
# It will NOT return a 404 if the user id is not found.
#

use strict;

use CGI;

require "config.pl";
require "database.pl";
require "openid_config.pl";
require "openid.pl";

#
# ProcessIdentityRequest
#
# This routine will process the request to retrieve the identity document.
#
sub ProcessIdentityRequest
{
    my ($username, $logoff) = @_;

    my ($name,
        $homepage,
        $status,
        $identity,
        $return_to);

    ($status, $name, $homepage) = GetUser($username);

    # do not expose invalid usernames to the web
    if ($status == 404 && length($username) > 2)
    {
        $status = 200;
        $homepage = "";
    }

    # do not expose private name info to the web
    $name = $username;

    if ($status == 404)
    {
        if (length($main::openid_not_found_template) > 0)
        {
            ShowNotFoundPage($username);
        }
        else
        {
            print "Status: 404 Not Found\r\n";
            print "\r\n";
        }
    }
    elsif ($status == 500)
    {
        print "Status: 500 Internal Server Error\r\n";
        print "\r\n";
    }
    else
    {
        if (!open(TEMPLATE, "<:encoding(UTF-8)", "$main::openid_identity_template"))
        {
            print "Status: 500 Internal Server Error\r\n";
            print "\r\n";
            return;
        }

        # If the user's actual name is not provided, just use the user ID
        if (length($name) == 0)
        {
            $name = $username;
        }

        print "X-XRDS-Location: $main::openid_xrds_url_prefix$username\r\n";
        print "Content-Type: text/html; charset=UTF-8\r\n";
        print "\r\n";

        while(<TEMPLATE>)
        {
            if (/CONTENT_TAG/)
            {
                # We will display the user's homepage (if provided), but
                # could show any content in this area.
                if (length($homepage) > 0)
                {
                    print "<p>Homepage: <a href=\"$homepage\">$homepage</a></p>\n";
                }

                # If requested to allow the user to log off, produce a form accordingly
                if ($logoff)
                {
                    $identity = $username;
                    $return_to = $main::openid_url_prefix . $identity;

                    MakeHTMLSafe(\$identity);
                    MakeHTMLSafe(\$return_to);

                    print << "HEREDOC";
<form name="openid_form" method="post" action="$main::process_login">
<input type="hidden" name="identity" value="$username" />
<input type="hidden" name="return_to" value="$return_to" />
<input type="submit" name="submit" value="Logoff" />
</form>
HEREDOC
                }
            }
            else
            {
                s/OPENID_NAME/$name/g;
                s/OPENID_ID/$username/g;
                s/OPENID_SITE_NAME/$main::openid_site_name/g;
                s/OPENID_OP_ENDPOINT/$main::op_endpoint/g;
                s/OPENID_URL_PREFIX/$main::openid_url_prefix/g;
                print;
            }
        }

        close(TEMPLATE);
    }
}

#
# MAIN
#
{
    my ($username,
        $openid_user,
        $query);

    $query = new CGI;

    $username = $query->param('username');
    $openid_user = $query->cookie('openid_user');

    # untaint username before using it
    $username =~ s{[^\w\-]}{}g;
    $username = substr($username,0,20) if (length($username) > 20);

    # untaint openid_user before using it
    $openid_user =~ s{[^\w\-]}{}g;
    $openid_user = substr($openid_user,0,20) if (length($openid_user) > 20);

    if (!DatabaseConnect())
    {
        die "Unable to connect to the database\n";
    }

    # Process the request
    ProcessIdentityRequest($username, ($openid_user eq $username) ? 1 : 0);
    
    # Disconnect from the database
    DatabaseDisconnect();
}
