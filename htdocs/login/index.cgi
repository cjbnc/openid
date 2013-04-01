#!/usr/bin/perl
#
# login
# Copyright (C) 2009, 2010, 2011
# Packetizer, Inc.
#
# Perform OpenID login-related functions.
# (Supports OpenID 2.0)
#

use strict;

use CGI;
use URI;
use URI::QueryParam;
use MIME::Base64;
use Digest::SHA qw( sha1 sha256 );
use Crypt::DH;
use Crypt::Random qw( makerandom_octet );
use Math::BigInt lib => 'GMP';

require "config.pl";
require "database.pl";
require "openid_config.pl";
require "openid.pl";

#
# BytesToInt
#
# This function will convert a string of bytes into number (uses BigInt).
# It will also ensure that the first byte we consider will result in
# a positive integer.  It returns "undef" is there is an error.
#
sub BytesToInt {
    my ($byte_string) = @_;
    my ($value);

    return undef if ( length($byte_string) == 0 );

    # Unpack the byte string as a string of bits, creating a new BigInt
    $value = Math::BigInt->new( '0b' . unpack( "B*", $byte_string ) );

    # Whatever we get should be a positive integer as per the OpenID spec
    return undef if ( $value <= 0 );

    return $value;
}

#
# IntToBytes
#
# This function will convert an integer into a string of bytes.
# If there is an error, it will return undef.
#
sub IntToBytes {
    my ($value) = @_;
    my ( $bit_string, $padding_bits );

    return undef if ( $value <= 0 );
    $bit_string = $value->as_bin;
    return undef unless $bit_string =~ s/^0b//;

    # We need to pad the bit string to ensure that it contains whole octets
    # and as per the OpenID spec, the leading bit must be 0 to ensure
    # it is not treated as a negative number.
    $padding_bits = length($bit_string) % 8;
    if ($padding_bits) {

        # We actually need to pad 8 - the modulo calculated above
        $padding_bits = 8 - $padding_bits;
    }
    elsif ( $bit_string =~ /^1/ ) {
        $padding_bits = 8;
    }
    while ( $padding_bits-- ) {
        $bit_string = "0" . $bit_string;
    }

    return pack( "B*", $bit_string );
}

#
# SupportedVersion
#
# Ensure this is a supported version of OpenID
#
sub SupportedVersion {
    my ($ns) = @_;

    foreach (@main::openid_ns_versions) {
        if ( $ns eq $_ ) {
            return 1;
        }
    }

    return 0;
}

#
# ValidRealm
#
# Check to ensure that the realm provided aligns with the return_to path
# as per section 9.2 of the OpenID 2.0 specification.
sub ValidRealm {
    my ( $realm, $return_to ) = @_;

    my ($realm_scheme,  $realm_host_port,  $realm_path,
        $return_scheme, $return_host_port, $return_path
    );

    if ( ( length($realm) == 0 ) || ( length($return_to) == 0 ) ) {

        # If either is not provided, then treat that as valid, as they are
        # not in conflict.
        return 1;
    }

    # Decompose the URLs
    # (Note the *. are optional wildcards at the beginning of realm URLs.)
    ( $realm_scheme, $realm_host_port, $realm_path )
        = (
        $realm =~ m/^([a-zA-Z]*):\/\/(\*?\.?[0-9a-zA-Z\-\.]+:?[0-9]*)(.*)$/ );

    $realm_scheme    = lc($realm_scheme);
    $realm_host_port = lc($realm_host_port);
    if ( length($realm_path) == 0 ) {
        $realm_path = "/";
    }

    ( $return_scheme, $return_host_port, $return_path )
        = (
        $return_to =~ m/^([a-zA-Z]*):\/\/([0-9a-zA-Z\-\.]+:?[0-9]*)(.*)$/ );

    $return_scheme    = lc($return_scheme);
    $return_host_port = lc($return_host_port);
    if ( length($return_path) == 0 ) {
        $return_path = "/";
    }

    if ( $realm_scheme ne $return_scheme ) {
        return 0;
    }

    if ( $realm_host_port ne $return_host_port ) {

        # If the realm contains a wildcard
        if ( $realm_host_port =~ /^\*\./ ) {
            $realm_host_port =~ s/^\*\.//;
            if ( !( $return_host_port =~ /$realm_host_port$/ ) ) {
                return 0;
            }
        }
        else {
            return 0;
        }
    }

    if ( !( $return_path =~ /^$realm_path/ ) ) {
        return 0;
    }

    return 1;
}

#
# ProduceErrorPage
#
# Produce an error page showing the specified string (direct error response)
#
sub ProduceErrorPage {
    my ( $error_string, %request ) = @_;

    print "Status: 400 Bad Request\r\n";
    print "Content-Type: text/plain; charset=UTF-8\r\n";
    print "\r\n";

    print "ns:$main::openid_ns\n";
    print "error:$error_string\n";
    if (   ( $request{'mode'} eq "associate" )
        && ( $request{'error_code'} eq "unsupported-type" ) )
    {

        # Whatever the remote signaled, we did not support. Let's offer SHA-1.
        print "error_code:unsupported-type\n";
        print "session_type:DH-SHA1\n";
        print "assoc_type:HMAC-SHA1\n";
    }
    print "contact:$main::contact\n";
}

#
# RedirectOnError
#
# Redirect the user on error (indirect error response)
#
sub RedirectOnError {
    my ( $error_string, %request ) = @_;
    my $location = URI->new( $request{'return_to'} );
    $location->query_param( 'openid.ns'      => $main::openid_ns );
    $location->query_param( 'openid.mode'    => 'error' );
    $location->query_param( 'openid.error'   => $error_string );
    $location->query_param( 'openid.contact' => $main::contact );

    print "Location: $location\r\n";
    print "\r\n";
}

#
# ReturnError
#
# This routine will return an error, either by redirecting the user agent
# or returning an error document.
#
sub ReturnError {
    my ( $error_string, %request ) = @_;

    if (   ( $request{'mode'} eq "associate" )
        && ( $request{'error_code'} eq "unsupported-type" ) )
    {

        # We must produce a direct error in this case se per the spec
        ProduceErrorPage( $error_string, %request );
    }
    elsif ( length( $request{'return_to'} ) > 0 ) {
        RedirectOnError( $error_string, %request );
    }
    else {
        ProduceErrorPage( $error_string, %request );
    }
}

#
# ProduceLoginPage
#
sub ProduceLoginPage {
    my ( $ns, $realm, $identity, $return_to, $assoc_handle, $message ) = @_;
    my ( $identity_1, $identity_2, $realm_display );

    if ( length($realm) == 0 ) {
        $realm_display = "(unspecified realm)";
    }
    else {
        $realm_display = $realm;
    }

    # Make sure input data is safe for HTML display and forms
    MakeHTMLSafe( \$realm );
    MakeHTMLSafe( \$identity );
    MakeHTMLSafe( \$return_to );
    MakeHTMLSafe( \$assoc_handle );

    print "Content-Type: text/html; charset=UTF-8\r\n";
    print "\r\n";

    open( TEMPLATE, "<:encoding(UTF-8)", "$main::openid_login_template" )
        || die "Could not open template";

    while (<TEMPLATE>) {
        if (/CONTENT_TAG/) {
            print "<p>\n";
            print "</p>\n";
            if ( length($identity) == 0 ) {
                $identity_1
                    = "<input type=\"text\" name=\"identity\" size=\"20\" value=\"\" style=\"width: 15em\" />";
                $identity_2 = "";
            }
            else {
                $identity_1 = $identity;
                $identity_2
                    = "<input type=\"hidden\" name=\"identity\" value=\"$identity\" />";
            }

            if ( length($message) > 0 ) {
                print "<p class=\"warning\">$message</p>\n";
            }

            print << "HEREDOC";
<form name="openid_form" method="post" action="$main::process_login">
<table>
<tr>
<td style="text-align: right; vertical-align: middle">
Log Into:
</td>
<td>
$realm_display
</td>
</tr>
<tr>
<td style="text-align: right; vertical-align: middle">
Login:
</td>
<td>
$identity_1
</td>
</tr>
<tr>
<td style="text-align: right; vertical-align: middle">
Password:
</td>
<td>
<input type="password" name="password" size="20" value="" style="width: 15em" />
</td>
</tr>
HEREDOC

            if (   ( length($main::openid_secure_cookie_domain) > 0 )
                && ( length($main::openid_insecure_cookie_domain) > 0 ) )
            {
                print << "HEREDOC";
<tr>
<td>
</td>
<td>
<input type="checkbox" name="sticky" value="Y"/> Remember this computer
</td>
</tr>
HEREDOC
            }

            print << "HEREDOC";
<tr>
<td>
</td>
<td>
<input type="submit" name="submit" value="Submit" />
<input type="submit" name="submit" value="Cancel" />
</td>
</tr>
</table>
$identity_2
<input type="hidden" name="ns" value="$ns" />
<input type="hidden" name="return_to" value="$return_to" />
<input type="hidden" name="realm" value="$realm" />
<input type="hidden" name="assoc_handle" value="$assoc_handle" />
</form>
HEREDOC
        }
        else {
            s/OPENID_SITE_NAME/$main::openid_site_name/g;
            print;
        }
    }

    close(TEMPLATE);
}

#
# GetIdentity
#
# Extract the identity value to utilize in the request message.
# If there is an error, the user will be notified and the return code
# will be 1.  If there is no error, the return code will be 0 and
# the identity string will be populated.  Note that an empty string
# is a valid identity string, which means that the identity of the
# user will be requested later.
#
sub GetIdentity {
    my (%request) = @_;
    my ($identity);

    # We must have either the Claimed ID or the OP-Local ID provided.
    # We will also accept the openid_user cookie and use that if no
    # other identity information can be determined from URI parameters.
    # We will not support an assertion that is not about an identifier
    # as described in the OpenID 2.0 spec Section 9.1.
    if (   ( length( $request{'identity'} ) == 0 )
        && ( length( $request{'claimed_id'} ) == 0 )
        && ( length( $request{'openid_user'} ) == 0 ) )
    {
        ReturnError( "Information required for authentication is missing.",
            %request );
        return ( 1, undef );
    }

    # Decide which identity value to utilize
    $identity = $request{'identity'};
    if ( length($identity) == 0 ) {
        $identity = $request{'claimed_id'};
    }

    if ( $identity eq "http://specs.openid.net/auth/2.0/identifier_select" ) {

        # Let the user specify his identity
        $identity = "";
    }

    # If we have not yet determined the identity from URI parameters,
    # try to use the cookie provided by the browser.
    if (   ( length($identity) == 0 )
        && ( length( $request{'openid_user'} ) > 0 ) )
    {
        $identity = $request{'openid_user'};
    }

    if ( length($identity) > 0 ) {
        $identity =~ s#$main::openid_url_prefix##;
        if ( $identity eq $request{'identity'} ) {
            ReturnError(
                "The specified user identity is not serviced by this OpenID server: "
                    . $request{'identity'} . ".",
                %request
            );
            return ( 1, undef );
        }
    }

    return ( 0, $identity );
}

#
# HandleCheckIDSetup
#
# This will handle the login request subsequent when the remote is
# associated with this server.
#
sub HandleCheckIDSetup {
    my (%request) = @_;
    my ( $result, $location, $identity );

    ( $result, $identity ) = GetIdentity(%request);
    return if ($result);

    # Make sure that the provided realm and the return_to align, as per
    # Section 9.2 of the OpenID 2.0 specification.
    if ( !ValidRealm( $request{'realm'}, $request{'return_to'} ) ) {
        ReturnError( "Realm provided does not match the return path.",
            %request );
        return;
    }

    # Redirect the user to validate the login if we have a user cookie and
    # we do not have a packetizer.message parameter (likely indicating
    # some error previously received from the login script).
    if (   ( length( $request{'openid_user'} ) > 0 )
        && ( length( $request{'packetizer.message'} == 0 ) ) )
    {
        $location = URI->new($main::process_login);
        $location->query_param( 'ns'           => $request{'ns'} );
        $location->query_param( 'identity'     => $identity );
        $location->query_param( 'assoc_handle' => $request{'assoc_handle'} );
        $location->query_param( 'realm'        => $request{'realm'} );
        $location->query_param( 'return_to'    => $request{'return_to'} );

        print "Location: $location\r\n";
        print "\r\n";
    }
    else {
        ProduceLoginPage(
            $request{'ns'}, $request{'realm'}, $identity,
            $request{'return_to'},
            $request{'assoc_handle'},
            $request{'packetizer.message'}
        );
    }
}

#
# HandleCheckIDImmediate
#
# This routine will respond to checkid_immediate requests.  Since all login
# and browser/site associations are handled via the openid_check script,
# we'll simply redirect the browser to that script.
#
sub HandleCheckIDImmediate {
    my (%request) = @_;

    my ( $location, $result, $identity );

    ( $result, $identity ) = GetIdentity(%request);
    return if ($result);

    if ( length($identity) == 0 ) {
        SignalSetupNeeded(%request);
        return;
    }

    # Make sure there is a return_to provided
    if ( length( $request{'return_to'} ) == 0 ) {
        ReturnError( "No return address specified.", %request );
        return;
    }

    # Make sure that the provided realm and the return_to align, as per
    # Section 9.2 of the OpenID 2.0 specification.
    if ( !ValidRealm( $request{'realm'}, $request{'return_to'} ) ) {
        ReturnError( "Realm provided does not match the return path.",
            %request );
        return;
    }

    $location = URI->new($main::process_login);
    $location->query_param( 'ns'           => $request{'ns'} );
    $location->query_param( 'identity'     => $identity );
    $location->query_param( 'assoc_handle' => $request{'assoc_handle'} );
    $location->query_param( 'realm'        => $request{'realm'} );
    $location->query_param( 'return_to'    => $request{'return_to'} );
    $location->query_param( 'mode'         => 'checkid_immediate' );

    print "Location: $location\r\n";
    print "\r\n";
}

#
# ValidAssocType
#
# Make sure this is a valid and supported association type
#
sub ValidAssocType {
    my ($assoc_type) = @_;

    foreach (@main::assoc_type) {
        if ( $assoc_type eq $_ ) {
            return 1;
        }
    }

    return 0;
}

#
# ValidSessionType
#
# Make sure this is a valid and supported association session type
#
sub ValidSessionType {
    my ($session_type) = @_;

    foreach (@main::session_type) {
        if ( $session_type eq $_ ) {
            return 1;
        }
    }

    return 0;
}

#
# HandleAssociate
#
# This routine will handle an 'associate' request from the Relying Party
#
sub HandleAssociate {
    my (%request) = @_;
    my ( $sth, $dh_consumer_public, $private_key, $public_key, $shared_secret,
        $p, $g, $dh, $hash, $mac_key, $enc_mac_key, $assoc_handle );

    # Some special considerations must be given to a 1.1 Relying Party
    if ( $request{'ns'} == $main::openid_ns_1_1 ) {

        # In the 1.1 spec, "no-encryption" session types did not exist.
        # Rather, the field was just absent or empty.  If this is a 1.1
        # Relying Party, let's set the session type internally to
        # "no-encryption" if it is missing, but we will not produce messages
        # with this session type
        if ( length( $request{'session_type'} ) == 0 ) {
            $request{'session_type'} = "no-encryption";
        }

        # In the 1.1 spec, if the assoc_type parameter is missing, the
        # OpenID Provider must assume HMAC-SHA1
        if ( length( $request{'assoc_type'} ) == 0 ) {
            $request{'assoc_type'} = "HMAC-SHA1";
        }
    }

    if ( !ValidAssocType( $request{'assoc_type'} ) ) {
        $request{'error_code'} = "unsupported-type";
        ReturnError( "Association type is not supported.", %request );
    }
    elsif ( !ValidSessionType( $request{'session_type'} ) ) {
        $request{'error_code'} = "unsupported-type";
        ReturnError( "Association session type is not supported.", %request );
    }
    elsif ( $request{'session_type'} eq "no-encryption" ) {
        ( $assoc_handle, $mac_key )
            = CreateAssociation( $request{'assoc_type'},
            $request{'session_type'} );
        if ( $assoc_handle == 0 ) {
            ReturnError( "Internal server error.", %request );
            return;
        }

        # Base64-encode the MAC key
        $enc_mac_key = encode_base64( $mac_key, '' );

        print "Content-Type: text/plain; charset=UTF-8\r\n";
        print "\r\n";

        print "ns:$main::openid_ns\n";
        print "assoc_handle:$assoc_handle\n";
        if (!(     ( $request{'session_type'} eq "no-encryption" )
                && ( $request{'ns'} eq $main::openid_ns_1_1 )
            )
            )
        {
            print "session_type:" . $request{'session_type'} . "\n";
        }
        print "assoc_type:" . $request{'assoc_type'} . "\n";
        print "expires_in:$main::assoc_expiration\n";
        print "mac_key:$enc_mac_key\n";
    }
    elsif ( length( $request{'dh_consumer_public'} ) == 0 ) {
        ReturnError( "DH public key not present in request.", %request );
    }
    else {
        if ( length( $request{'dh_modulus'} ) == 0 ) {
            $p = Math::BigInt->new($main::dh_modulus);
        }
        else {
            $p = BytesToInt( decode_base64( $request{'dh_modulus'} ) );
            if ( $p == undef ) {
                ReturnError( "Invalid prime number provided in the request.",
                    %request );
                return;
            }
        }

        if ( length( $request{'dh_gen'} ) == 0 ) {
            $g = Math::BigInt->new($main::dh_gen);
        }
        else {
            $g = BytesToInt( decode_base64( $request{'dh_gen'} ) );
        }

        # Make sure that g looks at least somewhat sane
        if ( ( $g == undef ) || ( $g > $p ) ) {
            ReturnError( "Invalid primitive root provided in the request.",
                %request );
            return;
        }

        $dh_consumer_public
            = BytesToInt( decode_base64( $request{'dh_consumer_public'} ) );
        if (   ( $dh_consumer_public == undef )
            || ( $dh_consumer_public <= 0 ) )
        {
            ReturnError( "Invalid public key provided in the request.",
                %request );
            return;
        }

        # Generate DH keys and the shared secret
        $dh = Crypt::DH->new;
        $dh->g($g);
        $dh->p($p);
        $dh->generate_keys;
        $public_key    = $dh->pub_key;
        $private_key   = $dh->priv_key;
        $shared_secret = $dh->compute_secret($dh_consumer_public);

        ( $assoc_handle, $mac_key )
            = CreateAssociation( $request{'assoc_type'},
            $request{'session_type'} );
        if ( $assoc_handle == 0 ) {
            ReturnError( "Internal server error.", %request );
            return;
        }

        # Create the enc_mac_key value
        if ( $request{'assoc_type'} eq "HMAC-SHA256" ) {
            $hash = sha256( IntToBytes($shared_secret) );
        }
        else {
            $hash = sha1( IntToBytes($shared_secret) );
        }
        $enc_mac_key = encode_base64( $hash ^ $mac_key, '' );

        print "Content-Type: text/plain; charset=UTF-8\r\n";
        print "\r\n";

        print "ns:$main::openid_ns\n";
        print "assoc_handle:$assoc_handle\n";
        print "session_type:" . $request{'session_type'} . "\n";
        print "assoc_type:" . $request{'assoc_type'} . "\n";
        print "expires_in:$main::assoc_expiration\n";
        print "dh_server_public:"
            . encode_base64( IntToBytes($public_key), '' ) . "\n";
        print "enc_mac_key:$enc_mac_key\n";
    }
}

#
# HandleCheckAuthentication
#
# This routine will check an association as requested by the remote entity.
# This will result in an immediate response back to the requestor.
#
sub HandleCheckAuthentication {
    my (%request) = @_;
    my ( $result, $assoc_handle );

    if ( $request{'op_endpoint'} ne $main::op_endpoint ) {
        $result = 0;
    }
    else {
        $result = VerifySignature(
            $request{'assoc_handle'},
            $request{'response_nonce'},
            $request{'signed'}, $request{'sig'}, $request{'identity'}
        );
    }

    if ($result) {
        print "Content-Type: text/plain; charset=UTF-8\r\n";
        print "\r\n";

        print "ns:$main::openid_ns\n";
        print "is_valid:true\n";
        if ( $request{'invalidate_handle'} > 0 ) {
            ($assoc_handle) = GetAssociation( $request{'invalidate_handle'} );
            if ( $assoc_handle == 0 ) {
                print "invalidate_handle:"
                    . $request{'invalidate_handle'} . "\n";
            }
        }
    }
    else {
        print "Content-Type: text/plain; charset=UTF-8\r\n";
        print "\r\n";

        print "ns:$main::openid_ns\n";
        print "is_valid:false\n";
    }
}

#
# MAIN
#
{
    my ( $query, %request );

    # Ensure that all output is proper UTF-8
    binmode( STDOUT, ":encoding(UTF-8)" );

    $query = new CGI;

    $request{'ns'}         = $query->param('openid.ns');
    $request{'mode'}       = $query->param('openid.mode');
    $request{'dh_modulus'} = $query->param('openid.dh_modulus');
    $request{'dh_gen'}     = $query->param('openid.dh_gen');
    $request{'dh_consumer_public'}
        = $query->param('openid.dh_consumer_public');
    $request{'session_type'} = $query->param('openid.session_type');
    $request{'assoc_type'}   = $query->param('openid.assoc_type');
    $request{'assoc_handle'} = $query->param('openid.assoc_handle');
    $request{'return_to'}    = $query->param('openid.return_to');
    $request{'claimed_id'}   = $query->param('openid.claimed_id');
    $request{'openid_user'}  = $query->cookie('openid_user');
    $request{'identity'}     = $query->param('openid.identity');
    $request{'realm'}        = $query->param('openid.realm');

    # OpenID 1.1 used a different name for realm, but the meaning was
    # identical.  We'll use the older name if it exists.
    if ( length( $request{'realm'} ) == 0 ) {
        $request{'realm'} = $query->param('openid.trust_root');
    }
    $request{'signed'}            = $query->param('openid.signed');
    $request{'sig'}               = $query->param('openid.sig');
    $request{'op_endpoint'}       = $query->param('openid.op_endpoint');
    $request{'response_nonce'}    = $query->param('openid.response_nonce');
    $request{'invalidate_handle'} = $query->param('openid.invalidate_handle');
    $request{'packetizer.message'} = $query->param('packetizer.message');

    # Since 1.1 implementations do not provide 'ns', we'll assume
    # that a missing ns indicates a 1.1 Relying Party
    if ( length( $request{'ns'} ) == 0 ) {
        $request{'ns'} = $main::openid_ns_1_1;
    }

    if ( length( $request{'mode'} ) == 0 ) {
        ReturnError( "Required OpenID parameters were not provided.",
            %request );
    }
    elsif ( !DatabaseConnect() ) {
        ReturnError( "Internal database error.", %request );
    }
    elsif ( !SupportedVersion( $request{'ns'} ) ) {
        ReturnError(
            "The service redirected to this page is using an unrecognized version of OpenID: "
                . $request{'ns'} . ".",
            %request
        );
    }
    elsif ( $request{'mode'} eq "associate" ) {
        HandleAssociate(%request);
    }
    elsif ( $request{'mode'} eq "checkid_setup" ) {
        HandleCheckIDSetup(%request);
    }
    elsif ( $request{'mode'} eq "checkid_immediate" ) {
        HandleCheckIDImmediate(%request);
    }
    elsif ( $request{'mode'} eq "check_authentication" ) {
        HandleCheckAuthentication(%request);
    }
    else {
        ReturnError( "Unsupported OpenID mode specified.", %request );
    }

    # Close the database connection
    DatabaseDisconnect();
}
