#!/usr/bin/perl
#
# OpenID Globals
# Copyright (C) 2009, 2010
# Packetizer, Inc.
#

use strict;

# Globals (should be modified)
$main::openid_site_name  = "NC State Unity";
$main::op_endpoint       = "https://webauth.ncsu.edu/openid/login/";
$main::contact           = "https://webauth.ncsu.edu/openid/contact.html";
$main::process_login     = "https://webauth.ncsu.edu/openid/checkid/";
$main::openid_url_prefix = "https://webauth.ncsu.edu/openid/";
$main::openid_setup_url = $main::openid_url_prefix;  # Used only in OpenID 1.1
$main::openid_xrds_url_prefix = "https://webauth.ncsu.edu/openid/xrds/";
$main::openid_identity_template
    = "/local/openid/templates/identity_template.html";
$main::openid_not_found_template = "/local/openid/htdocs/404.shtml";
$main::openid_login_template
    = "/local/openid/templates/login_template.html";
$main::openid_insecure_cookie_domain = ".ncsu.edu";
$main::openid_secure_cookie_domain   = "webauth.ncsu.edu";
$main::openid_cookie_expiration = 518400;    # Seconds until expiration

$main::openid_log_dir = "/local/openid/logs"; # writable by the webserver

# Globals (may be modified)
# If not using TLS for key exchange when creating an association, disallow
# no-encryption as per the OpenID spec
#@main::session_type = ("no-encryption", "DH-SHA1", "DH-SHA256");
@main::session_type = ( "DH-SHA1", "DH-SHA256" );
$main::assoc_expiration = 86400;   # Number of seconds an association is valid
$main::assoc_expiration_grace = 300;    # Allow for some grace period

# Globals (should not be modified)
$main::openid_ns          = "http://specs.openid.net/auth/2.0";
$main::openid_ns_1_1      = "http://openid.net/signon/1.1";
@main::openid_ns_versions = ( $main::openid_ns, $main::openid_ns_1_1 );
$main::dh_modulus
    = "0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB";
$main::dh_gen = "0x02";
@main::assoc_type = ( "HMAC-SHA1", "HMAC-SHA256" );

1;
