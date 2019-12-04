<?php
/**
 * Class for SamlSingleSignOnAuth extension
 *
 * @file
 * @ingroup Extensions
 */

//namespace MediaWiki\Session;

class SamlSingleSignOnAuthManager{

	private static $instance = null;

	private $attrs;

	private $relayState;

	private $firstName;

	private $lastName;

	private $userName;

	private $nameID;

	private $user_email;

	private $groupName;

	private $authFailed;

	public static function getInstance(){
		if( self::$instance === null){
			self::$instance = new SamlSingleSignOnAuthManager();
		}
		return self::$instance;
	}

	public function __construct(){

	}

	public function getConfig($configName) {
		switch($configName) {
			case 'loginURL':
				global $wgMoSamlLoginURL;
				return $wgMoSamlLoginURL;
			case 'logoutURL':
				global $wgMoSamlLogoutURL;
				return $wgMoSamlLogoutURL;
			case 'idpName':
				global $wgMoSamlIdpName;
				return $wgMoSamlIdpName;
			case 'isBrokerOn':
				global $wgMoSamlIsBrokerOn;
				return $wgMoSamlIsBrokerOn;
			case 'serverName':
				global $wgMoSamlServer;
				return $wgMoSamlServer;
			case 'hostName':
				global $wgMoSamlHostName;
				return $wgMoSamlHostName;
			case 'customerKey':
				global $wgMoSamlCustomerKey;
				return $wgMoSamlCustomerKey;
			case 'idpIssuer':
				global $wgMoSamlIssuer;
				return $wgMoSamlIssuer;
			case 'bindingType':
				global $wgMoSamlLoginBindingType;
				return $wgMoSamlLoginBindingType;
			case 'certDesc':
				global $wgMoSamlX509CertDesc;
				return $wgMoSamlX509CertDesc;
			case 'responseSigned':
				global $wgMoSamlIsResponseSigned;
				return $wgMoSamlIsResponseSigned;
			case 'assertionSigned':
				global $wgMoSamlIsAssertionSigned;
				return $wgMoSamlIsAssertionSigned;
			case 'updateUser':
				global $wgMoSamlUpdateUser;
				return $wgMoSamlUpdateUser;
			case 'autoCreateUser':
				global $wgMoSamlCreateUser;
				return $wgMoSamlCreateUser;
			case 'groupMap':
				global $wgMoSamlGroupMap;
				return $wgMoSamlGroupMap;
			case 'defaultGroup':
				global $wgMoSamlDefaultGroup;
				return $wgMoSamlDefaultGroup;
			case 'autoRedirect':
				global $wgMoSamlRegisteredOnlyAccess;
				return $wgMoSamlRegisteredOnlyAccess;
			default:
				return '';
		}
	}

	public function mo_saml_redirect_for_authentication($relayState){
		global $wgUser;
		if(empty($relayState)){
			$relayState = Title::newMainPage()->getFullUrl();
		}
		if(!$this->getConfig('isBrokerOn')){
			if($this->mo_saml_is_sp_configured() && !$wgUser->isLoggedIn()) {
				$sp_base_url = $this->getConfig('serverName');
				if(empty($sp_base_url)) {
					$sp_base_url = $wgServer;
				}
				$sendRelayState = $relayState;

				$ssoUrl = $this->getConfig('loginURL');
				$sso_binding_type = $this->getConfig('bindingType');
				$force_authn = false;//get_option('mo_saml_force_authentication');
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
		}else{
			$site_url = Title::newMainPage()->getFullUrl();
			$mo_redirect_url = $this->getConfig('moHostName') . "/moas/rest/saml/request?id=" . $this->getConfig('customerKey') . "&returnurl=" . urlencode( $site_url . "/?option=readsamllogin&returnto=" . urlencode ($relay_state) );
			header('Location: ' . $mo_redirect_url);
			exit();
		}
	}

	public function mo_saml_is_sp_configured() {
		if( !empty($this->getConfig('loginURL')) && !empty($this->getConfig('idpIssuer'))) {
			return 1;
		} else {
			return 0;
		}
	}

	/**
	 * Prints debugging information. $debugText is what you want to print, $debugVal
	 * is the level at which you want to print the information.
	 *
	 * @param string $debugText
	 * @param string $debugVal
	 * @param Array|null $debugArr
	 * @access private
	 */
	public function printDebug( $debugText, $debugArr = null ) {
		if ( !function_exists( 'wfDebugLog' ) ) {
			return;
		}

		//global $wgLDAPDebug;

		//if ( $wgLDAPDebug >= $debugVal ) {
			if ( isset( $debugArr ) ) {
				$debugText = $debugText . " " . implode( "::", $debugArr );
			}
			wfDebugLog( 'miniorange_saml', '1.0.0' . ' ' . $debugText, false );
		//}
	}

	public function mo_saml_validate_saml_response($user) {
		global $wgServer, $wgMoSamlIssuer;

		$sp_base_url = $this->getConfig('serverName');
		if(empty($sp_base_url)) {
			$sp_base_url = $wgServer;
		}
		$samlResponse = $_REQUEST['SAMLResponse'];
		$samlResponse = base64_decode($samlResponse);
		
		if(array_key_exists('SAMLResponse', $_GET) && !empty($_GET['SAMLResponse'])) {
			$samlResponse = gzinflate($samlResponse);
		}
		
		$document = new DOMDocument();
		$document->loadXML($samlResponse);
		$samlResponseXml = $document->firstChild;
		
		if($samlResponseXml->localName == 'LogoutResponse') {
			//wp_logout(); --- replace with Mediawiki equivalent
			header('Location: ' . $this->getConfig('serverName'));
			exit;
		} else {
			// It's a SAML Assertion
			if(array_key_exists('RelayState', $_POST) && !empty( $_POST['RelayState'] ) && $_POST['RelayState'] != '/') {
				$this->relayState = $_POST['RelayState'];
			} else {
				$this->relayState = '';
			}
			
			$certFromPlugin = $this->getConfig('certDesc');
			$certfpFromPlugin = XMLSecurityKey::getRawThumbprint($certFromPlugin);
			
			$acsUrl = $sp_base_url .'/';
			$samlResponse = new SAML2_Response($samlResponseXml);
			
			$responseSignatureData = $samlResponse->getSignatureData();
			$assertionSignatureData = current($samlResponse->getAssertions())->getSignatureData();

			/* convert to UTF-8 character encoding*/
			$certfpFromPlugin = iconv("UTF-8", "CP1252//IGNORE", $certfpFromPlugin);
			
			/* remove whitespaces */
			$certfpFromPlugin = preg_replace('/\s+/', '', $certfpFromPlugin);	
			
			$responseSignedOption = $this->getConfig('responseSigned');
			$assertionSignedOption = $this->getConfig('assertionSigned');
 			
			/* Validate signature */
			if($responseSignedOption == 'checked') {
				$validSignature = MoSamlUtilities::processResponse($acsUrl, $certfpFromPlugin, $responseSignatureData, $samlResponse);
				if($validSignature === FALSE) {
					echo "Invalid signature in the SAML Response.";
					$this->authFailed = true;
					exit;
				}
			}
			
			if($assertionSignedOption == 'checked') {
				$validSignature = MoSamlUtilities::processResponse($acsUrl, $certfpFromPlugin, $assertionSignatureData, $samlResponse);
				if($validSignature === FALSE) {
					echo "Invalid signature in the SAML Assertion.";
					$this->authFailed = true;
					exit;
				}
			}
			
			// verify the issuer and audience from saml response
			$issuer = $this->getConfig('idpIssuer');
			$spEntityId = $sp_base_url . '/extensions/SamlSingleSignOnAuth/';
		
			if(!MoSamlUtilities::validateIssuerAndAudience($samlResponse,$spEntityId, $issuer)){
				$this->authFailed = true;
				exit;
			}
			
			$ssoemail = current(current($samlResponse->getAssertions())->getNameId());
			$this->attrs = current($samlResponse->getAssertions())->getAttributes();
			$this->attrs['NameID'] = array("0" => $ssoemail);
			$sessionIndex = current($samlResponse->getAssertions())->getSessionIndex();

			return true;
		}
	}

	public function mo_saml_set_attributes($user){
		global $wgMoSamlEmailAttr, $wgMoSamlFNameAttr, $wgMoSamlLNameAttr, $wgMoSamlUsernameAttr, $wgMoSamlGroupAttr, $wgMoSamlDefaultGroup, $wgContLang;
		try {
			$this->printDebug( "Entering mo_saml_set_attributes");
			//Get enrypted user_email
			$emailAttribute = $wgMoSamlEmailAttr;
			$usernameAttribute = $wgMoSamlUsernameAttr;
			$firstName = $wgMoSamlFNameAttr;
			$lastName = $wgMoSamlLNameAttr;
			$groupName = $wgMoSamlGroupAttr;
			$defaultRole = $wgMoSamlDefaultGroup;
			$dontAllowUnlistedUserRole = false;
			$user_email = '';
			$userName = '';
			
			$attrs = $this->attrs;

			//Attribute mapping. Check if Match/Create user is by username/email:
			if(!empty($attrs)){
				if(!empty($firstName) && array_key_exists($firstName, $attrs))
					$this->firstName = $attrs[$firstName][0];
				else
					$this->firstName = '';

				if(!empty($lastName) && array_key_exists($lastName, $attrs))
					$this->lastName = $attrs[$lastName][0];
				else
					$this->lastName = '';

				if(!empty($usernameAttribute) && array_key_exists($usernameAttribute, $attrs))
					$this->userName = $attrs[$usernameAttribute][0];
				else
					$this->userName = $attrs['NameID'][0];

				if(!empty($emailAttribute) && array_key_exists($emailAttribute, $attrs))
					$this->user_email = $attrs[$emailAttribute][0];
				else
					$this->user_email = $attrs['NameID'][0];
				
				if(!empty($groupName) && array_key_exists($groupName, $attrs))
					$this->groupName = $attrs[$groupName];
				else
					$this->groupName = array();

				$this->nameID = $attrs['NameID'][0];
			}

			$this->printDebug( "Set attributes");

			if($this->relayState=='testValidate'){
				//??mo_saml_show_test_result($firstName,$lastName,$user_email,$groupName,$attrs);
			}else{
				if ( !User::isUsableName( $wgContLang->ucfirst( $this->userName  ) ) ) {
					echo 'Illegal username: ' . $this->userName;
					exit();
				}
				return $this->userName;
				
			}

		}
		catch (Exception $e) {
			return "An error occurred while processing the SAML Response.";
			exit;
		}
	}

	public function updateUserInfo($user) {
		$this->printDebug("Entering updateUserInfo");
		if ( $this->authFailed ) {
			$this->printDebug( "User didn't successfully authenticate, exiting.");
			return;
		}

		if($this->getConfig('updateUser')){
			$this->printDebug( "Setting user preferences.");
			if ( is_string( $this->firstName ) ) {
				$this->printDebug( "Setting nickname.");
				$user->setOption( 'nickname', $this->firstName );
			}

			if ( is_string( $this->nameID ) ) {
				$this->printDebug( "Setting nameID.");
				$user->setOption( 'name_id', $this->nameID );
			}

			if ( is_string( $this->firstName ) || is_string( $this->lastName ) ) {
				$this->printDebug( "Setting realname.");
				$user->setRealName( $this->firstName . ' ' . $this->lastName );
			}
			if ( is_string( $this->user_email ) ) {
				$this->printDebug( "Setting email.");
				$user->setEmail( $this->user_email );
				$user->confirmEmail();
			}
		}

		//set user groups
		$this->printDebug( "Setting user groups.");
		$this->setGroups($user);

		# Let other extensions update the user
		Hooks::run( 'LDAPUpdateUser', array( &$user ) );

		$this->printDebug( "Saving user settings.");
		$user->saveSettings();
	}

	public function initializeUser( &$user, $autocreate = false ) {
		$this->printDebug( "Entering initUser");

		if ( $this->authFailed ) {
			$this->printDebug( "User didn't successfully authenticate, exiting.");
			return;
		}

		// The update user function does everything else we need done.
		$this->updateUserInfo( $user );

		// updateUser() won't necessarily save the user's settings
		$user->saveSettings();
	}

	public function setGroups( &$user ){
		global $wgGroupPermissions;
		$groupMap = $this->getConfig('groupMap');
		//echo 'groupMap:';
		//print_r($groupMap);

		# add groups permissions
		$localAvailGrps = $user->getAllGroups();
		$localUserGrps = $user->getEffectiveGroups();
		//print_r($localAvailGrps);exit();
		$defaultGroup = $this->getConfig('defaultGroup');
		if(!in_array( $defaultGroup, $localUserGrps ))
			$user->addGroup( $defaultGroup );

		/*foreach($groupMap as $localGrp => $samlGrpArray){
			if(!in_array( $localGrp, $localUserGrps )){
				foreach ($samlGrpArray as $key => $samlGrp) {	//what is key?
					if(is_array($this->groupName){
						if(in_array( $samlGrp, $this->groupName )){
							$user->addGroup( $localGrp );
							break;
						}
					} else {
						if($samlGrp == $this->groupName){
							$user->addGroup( $localGrp );
							break;
						}
					}
				}
			}
		}*/

		/*echo '<br><br>$localAvailGrps: ';
		print_r($localAvailGrps);
		echo '<br><br>$localUserGrps: ';
		print_r($localUserGrps);
		exit();*/
	}
}
