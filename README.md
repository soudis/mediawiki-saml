SamlSingleSignOnAuth by miniOrange enables MediaWiki to use SAML 2.0 to SSO with SAML complaint IDP.

Required
--------
MediaWiki 1.25+

Download the extension ZIP and extract ZIP to mediawiki host under extensions folder (e.g. mediawiki/extensions). Folder extracted should be SamlSingleSignOnAuth.

Add following configuration to LocalSettings.php and change configuration values:
---------------------------------------------------------------------------------

# miniOrange SAML Extension settings
# Loads SAML extension
wfLoadExtension( 'SamlSingleSignOnAuth' );

# Enter IDP Name
$wgMoSamlIdpName = 'miniOrange';

# Enter SAML Issuer URL or Entity ID
$wgMoSamlIssuer = 'https://auth.miniorange.com/moas';

# Enter SAML Login URL or ACS(Assertion Consumer Service) URL here 
$wgMoSamlLoginURL = 'https://auth.miniorange.com/moas/idp/samlsso';

# Set binding type for login. Two possible values - HttpRedirect and HttpPost
$wgMoSamlLoginBindingType = 'HttpRedirect';

# Enter certificate information. Open certificate in notepad and copy certificate
$wgMoSamlX509CertDesc = '-----BEGIN CERTIFICATE-----
. . . . 
. . . . 
. . . .
-----END CERTIFICATE-----';

# Only set to true if SAML is brokered through miniOrange
$wgMoSamlIsBrokerOn = false;

# OPTIONAL - Enter Relay State if applicable
$wgMoSamlRelayState = '';

# Set true if Response is signed, set false by default
$wgMoSamlIsResponseSigned = false;

# Set true if Assertion is signed, set true by default
$wgMoSamlIsAssertionSigned = true;

# Set this to true if you want to update user with incoming attributes whenever user logs in
$wgMoSamlUpdateUser = true;

# Auto create user if the user does not exist
$wgMoSamlCreateUser = true;

# Map attributes
$wgMoSamlEmailAttr = 'email';
$wgMoSamlUsernameAttr = 'username';
$wgMoSamlFNameAttr = 'fname';
$wgMoSamlLNameAttr = 'lname';
$wgMoSamlGroupAttr = 'role';

# Set default group for users
$wgMoSamlDefaultGroup = 'user';

# OPTIONAL - Set this to override $wgServer as site URL in the extension. Please make sure this is 
# the URL where MediaWiki is hosted and '/extensions/SamlSingleSignOnAuth/' can be appended to it.
$wgMoSamlServer = 'http://&lt;MEDIAWIKI_DOMAIN&gt;/mediawiki';

# Optional - host name - DO NOT CHANGE THIS
$wgMoSamlHostName = 'https://auth.miniorange.com';

# Only required for SAML broker flow
$wgMoSamlCustomerKey = 12345;

# Set this to true if you don't want your users to view website without being logged in using SAML.
# Users will be redirected to the IdP if user is not logged in. Make sure logout is enabled for this.
$wgMoSamlRegisteredOnlyAccess = false;

Versions
---------
1.1.1 
- Fix for HTML not getting loaded on login page

For any queries or issues, please drop an email at info@miniorange.com or you can submit a query at https://www.miniorange.com/contact.