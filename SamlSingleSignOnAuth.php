<?php
/**
 * SamlSingleSignOnAuth
 *
 * SAML authentication MediaWiki extension.
 *
 * @file
 * @ingroup Extensions
 * @defgroup SamlSingleSignOnAuth
 *
 *
 * @package SamlSingleSignOnAuth
 */

if ( !defined( 'MEDIAWIKI' ) ) {
	die( "This is a MediaWiki extension, and must be run from within MediaWiki.\n" );
}

if ( function_exists( 'wfLoadExtension' ) ) {
	wfLoadExtension( 'SamlSingleSignOnAuth' );
	// Keep i18n globals so mergeMessageFileList.php doesn't break
	$wgMessagesDirs['SamlSingleSignOnAuth'] = __DIR__ . '/i18n';
	$wgExtensionMessagesFiles['SamlSingleSignOnAuthAlias'] = __DIR__ . '/SamlSingleSignOnAuth.i18n.alias.php';

	wfWarn(
		'Deprecated PHP entry point used for SamlSingleSignOnAuth extension. Please use wfLoadExtension ' .
		'instead, see https://www.mediawiki.org/wiki/Extension_registration for more details.'
	);
	return true;
} else {
	die( 'This version of the SamlSingleSignOnAuth extension requires MediaWiki 1.25+' );
}
