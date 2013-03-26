#!/usr/bin/perl
#
# xrds
# Copyright (C) 2009
# Packetizer, Inc.
#
# Produce the XRDS document for the specified user.
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
sub ProcessXRDSRequest
{
    my ($username) = @_;

    my ($name,
        $homepage,
        $status);

    ($status, $name, $homepage) = GetUser($username);

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
        print "Content-Type: application/xrds+xml; charset=UTF-8\r\n";
        print "\r\n";
        print << "HERE_DOC";
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS 
    xmlns:xrds="xri://\$xrds"
    xmlns="xri://\$xrd*(\$v*2.0)"
    xmlns:openid="http://openid.net/xmlns/1.0">
  <XRD>
    <!-- OpenID 2.0 login service -->
    <Service priority="10">
      <Type>http://specs.openid.net/auth/2.0/signon</Type>
      <URI>$main::op_endpoint</URI>
      <LocalID>$main::openid_url_prefix$username</LocalID>
    </Service>
    <!-- OpenID 1.1 login service -->
    <Service priority="20">
      <Type>http://openid.net/signon/1.1</Type>
      <URI>$main::op_endpoint</URI>
      <openid:Delegate>$main::openid_url_prefix$username</openid:Delegate>
    </Service>
  </XRD>
</xrds:XRDS>
HERE_DOC
    }
}

#
# MAIN
#
{
    my ($username,
        $query);

    $query = new CGI;

    $username = $query->param('username');

    if (!DatabaseConnect())
    {
        die "Unable to connect to the database\n";
    }

    # Process the request
    ProcessXRDSRequest($username);
    
    # Disconnect from the database
    DatabaseDisconnect();
}
