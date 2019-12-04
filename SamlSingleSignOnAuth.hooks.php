<?php
/**
 * Hooks for SamlSingleSignOnAuth extension
 *
 * @file
 * @ingroup Extensions
 */

class SamlSingleSignOnAuthHooks {

	public static function hookLoginForm( &$template ) {
		global $wgUser, $wgOut;
		$moSaml = SamlSingleSignOnAuthManager::getInstance();
		if ( $moSaml->getConfig('autoRedirect') && !$wgUser->isLoggedIn()) {
			$relayState = Title::newMainPage()->getFullUrl();
			$moSaml->mo_saml_redirect_for_authentication($relayState);
		} else {
			$template->set(
				'extrafields',
				'<a class="mw-ui-button mw-ui-constructive" href="#" onclick="document.getElementById(\'mologin\').submit()">'
				. wfMessage( 'mosaml-login-btn', $moSaml->getConfig('idpName') )->escaped()
				. '</a>'
			);

			$wgOut->addHTML('<form name="mologin" id="mologin" method="POST" action=""><input type="hidden" name="option" value="saml_user_login"/></form>');

			/*$wgOut->addScript("<script type=\"text/javascript\">\n".
				"window.onload = function(){\n".
				"my_form=document.createElement('FORM');\n".
				"my_form.name='mologin';\n".
				"my_form.method='POST';\n".
				"my_form.action='';\n".
				"my_form.id='mologin';\n".
				"my_tb=document.createElement('INPUT');\n".
				"my_tb.type='hidden';\n".
				"my_tb.name='option';\n".
				"my_tb.value='saml_user_login';\n".
				"my_form.appendChild(my_tb);\n".
		       "document.body.appendChild(my_form);\n".
		       "}\n".
		       "</script>");*/
		}

		return true;
	}

    public static function hookUserLogout($user) {
    	global $wgServer, $wgOut;
		$moSaml = SamlSingleSignOnAuthManager::getInstance();
		$sp_base_url = $moSaml->getConfig('serverName');
		if(empty($sp_base_url)) {
			$sp_base_url = $wgServer;
		}				
		$acsUrl = $sp_base_url . "/";
		$issuer = $sp_base_url . '/extensions/SamlSingleSignOnAuth/';
		$ssoUrl = $moSaml->getConfig('logoutURL');			

		$sendRelayState = $sp_base_url;				

		$requestXML = MoSamlUtilities::createLogoutRequest( $user->getOption('name_id'),'', $issuer, $ssoUrl);

		$samlRequest = "SAMLRequest=" . $requestXML . "&RelayState=" . urlencode($sendRelayState) . '&ReturnTo=' . $sp_base_url . '&SigAlg='. urlencode(XMLSecurityKey::RSA_SHA256);
		$param =array( 'type' => 'private');
		$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, $param);
		$certFilePath = __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'sp-key.key';

		$key->loadKey($certFilePath, TRUE);
		$objXmlSecDSig = new XMLSecurityDSig();
		$signature = $key->signData($samlRequest);
		$signature = base64_encode($signature);
		$redirect = $ssoUrl;
		if (strpos($ssoUrl,'?') !== false) {
			$redirect .= '&';
		} else {
			$redirect .= '?';
		}

		$redirect .= $samlRequest . '&Signature=' . urlencode($signature);			

		
		$wgOut->redirect($redirect);

		return true;

    }

	public static function hookUserLoad( $user, &$result = null ){
		global $wgUser, $wgBlockDisablesLogin, $wgCookieSecure, $wgCookieExpiration, $wgServer, $wgCookiePrefix;
		if(isset($_REQUEST['option']) && $_REQUEST['option'] == 'saml_user_login' || !$wgUser->isLoggedIn() && !array_key_exists('SAMLResponse', $_REQUEST) &&  !array_key_exists('SAMLRequest', $_REQUEST)){
			$moSaml = SamlSingleSignOnAuthManager::getInstance();
			if($moSaml->mo_saml_is_sp_configured() ) {
				$sp_base_url = $moSaml->getConfig('serverName');
				if(empty($sp_base_url)) {
					$sp_base_url = $wgServer;
				}
				/*if($_REQUEST['option'] == 'testConfig')
					$sendRelayState = 'testValidate';
				else*/ 
				if ( isset( $_REQUEST['returnto']) ) 
					$sendRelayState = $_REQUEST['returnto'];
				else 
					$sendRelayState = $sp_base_url;
				
				$ssoUrl = $moSaml->getConfig('loginURL');
				$sso_binding_type = $moSaml->getConfig('bindingType');				
				$force_authn = false;
				$acsUrl = $sp_base_url . "/";
				$issuer = $sp_base_url . '/extensions/SamlSingleSignOnAuth/';
				$samlRequest = MoSamlUtilities::createAuthnRequest($acsUrl, $issuer, $ssoUrl, $force_authn, $sso_binding_type);
				
				if(empty($sso_binding_type) || $sso_binding_type == 'HttpRedirect') {
					$samlRequest = "SAMLRequest=" . $samlRequest . "&RelayState=" . urlencode($sendRelayState) . '&SigAlg='. urlencode(XMLSecurityKey::RSA_SHA256);
					$param =array( 'type' => 'private');
					$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, $param);
					$certFilePath = __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'sp-key.key';
					$key->loadKey($certFilePath, TRUE);
					$objXmlSecDSig = new XMLSecurityDSig();
					$signature = $key->signData($samlRequest);
					$signature = base64_encode($signature);
					$redirect = $ssoUrl;
					if (strpos($ssoUrl,'?') !== false) {
						$redirect .= '&';
					} else {
						$redirect .= '?';
					}
					$redirect .= $samlRequest . '&Signature=' . urlencode($signature);
					header('Location: '.$redirect);
					exit();
				} else {
					$privateKeyPath = __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'sp-key.key';
					$publicCertPath = __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'sp-certificate.crt';
					
					$base64EncodedXML = MoSamlUtilities::signXML( $samlRequest, $publicCertPath, $privateKeyPath, 'NameIDPolicy' );
					
					MoSamlUtilities::postSAMLRequest($ssoUrl, $base64EncodedXML, $sendRelayState);
				}
			}
		} else if(array_key_exists('SAMLResponse', $_REQUEST) && !empty($_REQUEST['SAMLResponse'])) {
			if(!$wgUser->isLoggedIn()){
				$moSaml = SamlSingleSignOnAuthManager::getInstance();
				$moSaml->mo_saml_validate_saml_response($user);
				$userName = $moSaml->mo_saml_set_attributes($user);
				//echo $result;echo '  ummm, here';exit();
				if($userName) {
					if ( $wgBlockDisablesLogin && $user->isBlocked() ) {
						$block = $user->getBlock();
						throw new UserBlockedError( $block );
					} else {
						if ( session_id() == '') {
							//wfSetupSession();
						}

						$id = User::idFromName( $userName );
						if ( $id ) {
							$moSaml->printDebug( "User exists in local database, logging in.");
							$user->setId( $id );
							$user->loadFromId();
							$user->setCookies();
							$moSaml->updateUserInfo($user);
							$user->saveSettings();
							$result = true;
						} else {
							$userAdded = self::addUser($user, $userName);
							if ( !$userAdded ) {
								$result = false;
								return false;
							}
						}
					}
				} else {
					return true;
				}
			}
			return true;
		} else if(array_key_exists('SAMLRequest', $_REQUEST) && !empty($_REQUEST['SAMLRequest'])) {
			//$urlDecoded = urldecode($_REQUEST['SAMLRequest']);
			$samlRequest = base64_decode($_REQUEST['SAMLRequest']);
   		    $samlRequest = gzinflate($samlRequest);			
			$document = new DOMDocument();
			$document->loadXML($samlRequest);	
			$requestXML = $document->firstChild;	
				//echo('TEST7'.$requestXML->localName);
			$moSaml = SamlSingleSignOnAuthManager::getInstance();
			if($requestXML->localName == 'LogoutRequest') 	{
				$sp_base_url = $moSaml->getConfig('serverName');
				if(empty($sp_base_url)) {
					$sp_base_url = $wgServer;
				}				
				$acsUrl = $sp_base_url . "/";
				$issuer = $sp_base_url . '/extensions/SamlSingleSignOnAuth/';
				$ssoUrl = $moSaml->getConfig('logoutURL');				
				/*if($_REQUEST['option'] == 'testConfig')
					$sendRelayState = 'testValidate';
				else*/ 
				if ( isset( $_REQUEST['returnto']) ) 
					$sendRelayState = $_REQUEST['returnto'];
				else 
					$sendRelayState = $sp_base_url;				

				$certFilePath = __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'sp-key.key';				

				$logoutRequest = new SAML2_LogoutRequest($requestXML);
				$user->logout();
				$responseXML = MoSamlUtilities::createLogoutResponse( $requestXML->getAttribute('ID'), $issuer, $ssoUrl, $slo_binding_type = 'HttpRedirect');

				$samlResponse = "SAMLRequest=" . $responseXML . "&RelayState=" . urlencode($sendRelayState) . '&SigAlg='. urlencode(XMLSecurityKey::RSA_SHA256);
				$param =array( 'type' => 'private');
				$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, $param);
				$certFilePath = __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'sp-key.key';

				$key->loadKey($certFilePath, TRUE);
				$objXmlSecDSig = new XMLSecurityDSig();
				$signature = $key->signData($samlResponse);
				$signature = base64_encode($signature);
				$redirect = $ssoUrl;
				if (strpos($ssoUrl,'?') !== false) {
					$redirect .= '&';
				} else {
					$redirect .= '?';
				}

				$redirect .= $samlResponse . '&Signature=' . urlencode($signature);			
								echo('TEST6'.$redirect);

				header('Location: '.$redirect);
				exit();
			}
			
			return true;
		}

	}

	public static function addUser( $user, $userName ) {
		$moSaml = SamlSingleSignOnAuthManager::getInstance();

		if ( !$moSaml->getConfig('autoCreateUser') ) {
			$moSaml->printDebug( "Cannot automatically create accounts.");
			return false;
		}

		$moSaml->printDebug( "User does not exist in local database; creating." );
		// Checks passed, create the user
		$user->loadDefaults( $userName );
		$status = $user->addToDatabase();
		if ( $status !== null && !$status->isOK() ) {
			$moSaml->printDebug( "Creation failed: " . $status->getWikiText() );
			return false;
		}
		$moSaml->initializeUser( $user, true );
		$user->setCookies();
		# Update user count
		$ssUpdate = new SiteStatsUpdate( 0, 0, 0, 0, 1 );
		$ssUpdate->doUpdate();
		# Notify hooks (e.g. Newuserlog)
		Hooks::run( 'AuthPluginAutoCreate', array( $user ) );

		return true;
	}

}
