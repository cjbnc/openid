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
sub ProcessXRDSRequest {
    my ($username) = @_;

    my ( $name, $homepage, $status );

    ( $status, $name, $homepage ) = GetUser($username);

    # do not expose invalid usernames to the web
    if ( $status == 404 && length($username) > 2 ) {
        $status   = 200;
        $homepage = "";
    }

    # do not expose private name info to the web
    $name = $username;

    if ( $status == 404 ) {
        if ( length($main::openid_not_found_template) > 0 ) {
            ShowNotFoundPage($username);
        }
        else {
            print "Status: 404 Not Found\r\n";
            print "\r\n";
        }
    }
    elsif ( $status == 500 ) {
        print "Status: 500 Internal Server Error\r\n";
        print "\r\n";
    }
    else {
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
    my ( $username, $query );

    $query = new CGI;

    $username = $query->param('username');

    # untaint username before using it
    $username =~ s{[^\w\-]}{}g;
    $username = substr( $username, 0, 20 ) if ( length($username) > 20 );

    if ( !DatabaseConnect() ) {
        die "Unable to connect to the database\n";
    }

    # Process the request
    ProcessXRDSRequest($username);

    # Disconnect from the database
    DatabaseDisconnect();
}
