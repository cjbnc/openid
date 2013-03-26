Introduction
------------

This product is free open source software.  For license information, see
the file called license.txt.

For complete documentation of the system, refer to the included PDF file.


Version History
---------------

Version  Date        Comments
-------  ----------  ----------------------------------------------------------
1.8      2011-01-06  Modified the code so that Cookies will only be
                     sent to the User Agent if both the secure and
                     insecure cookie domain variables are defined.
1.7      2010-12-30  Renamed the checkid directory and separated the
                     global variables into a separate config file.
1.6      2010-05-14  Corrected an error where the OpenID server would reject
                     association requests over TLS.  In that case, the
                     value dh_consumer_public is not required, but the
                     server was requiring it.
1.5      2010-05-10  Moved the OpenID password checking script to
                     a new directory called openid_check.
1.4      2010-03-28  Added support for checkid_immediate and cookies
                     to allow one to automatically log into sites
                     without being prompted for a password after
                     successfully logging in.  This works only when the
                     user selects the "remember this computer" option.
1.3      2010-03-26  Some RPs do not establish associations before directing
                     the user to the OpenID server.  In those cases,
                     an association is created using defaults and returned
                     in the response, should the RP wish to verify the
                     signature.
1.2      2010-02-09  The openid_sigs table was missing in the misc directory
1.1      2010-01-19  Fixed a bug where the OpenID server was not properly
                     responding to login requests where the RP set the
                     identity value to "identifier_select".  Specifically,
                     the GetIdentity function was returning the wrong
                     indicator to the calling routine and there was also
                     an error in the login form that was generated.
                     The only changes were made to the file named
                     htdocs/login/index.cgi.

1.0      2009-12-26  Initial release
