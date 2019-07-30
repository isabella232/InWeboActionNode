/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2019 ForgeRock AS.
 */


package com.sorluc.InWeboAuthNode;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that triggers InWebo Push authentication. 
 */
@Node.Metadata(outcomeProvider  = InWeboActionNode.InWeboActionNodeOutcomeProvider.class,
               configClass      = InWeboActionNode.Config.class)
	public class InWeboActionNode implements Node {

    private final Logger logger = LoggerFactory.getLogger(InWeboActionNode.class);
    private final Config config;
    private final Realm realm;
    
    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * 
         * List of attributes to set.
         */
    	@Attribute(order = 100)
        default boolean isInAM() {
            return false;
        }
        
        @Attribute(order = 200)
        default InWeboAction actionSelection() {
            return InWeboAction.PUSH;
        }
        
        @Attribute(order = 300)
        String inWeboAction();
        
        @Attribute(order = 400, validators = RequiredValueValidator.class)
        default String inWeboURL() {
            return "https://api.myinwebo.com/FS";
        }
        
        @Attribute(order = 500, validators = RequiredValueValidator.class)
        default String serviceId() {
            return "5536";
        }
        
        @Attribute(order = 600, validators = RequiredValueValidator.class)
        default String keyStoreAbsolutePath() {
            return "/home/sorluc/Forgerock_2019.p12";
        }
        
        @Attribute(order = 700, validators = RequiredValueValidator.class)
        @Password
        char[] keyStorePassword();

        /*
        @Attribute(order = 800)
        default String trustStoreAbsolutePath() {
            return "/etc/alternatives/jre/lib/security/cacerts";
        }
        
        @Attribute(order = 900, validators = RequiredValueValidator.class)
        @Password
        char[] trustStorePassword();
        */
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public InWeboActionNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
    	
		Document docInWebo = null;
		String username = null;
		String otp = null;
        String inWeboSessionId = null;
			
    	logger.trace("====================================== InWebo Process start ======================================\n");
    	traceDumpShareState(context);    	
    	username = context.sharedState.get("username").asString();
    	// TODO don't use sharestate to store otp and implement a callback
    	otp = context.sharedState.get("otp").asString();
    	inWeboSessionId = context.sharedState.get("inWeboSessionId").asString();
    	
    	// If it is requested that the user is in AM
    	if(config.isInAM()){
    		AMIdentity userIdentity = null;
    		IdUtils.getIdentity(username, realm.asDN());
    		logger.trace("process: after getIdentity");
    		try {
				if(userIdentity == null || !userIdentity.isExists() || !userIdentity.isActive()) {
					logger.error("Failed - process: user " + username + " doesn't exist but isInAM is required");
				    return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
				}
			} catch (SSOException | IdRepoException e) {
				logger.error("Failed - process: SSOException | IdRepoException " + e.getMessage());
			    return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
			}
    	}
    	
    	// Create the SSL Factory for the double handshake with InWebo
    	SSLSocketFactory sf = null;
    	sf = createInWeboSSLSocketFactory(
    			"PKCS12", config.keyStoreAbsolutePath(), config.keyStorePassword());
//    			"JKS", config.trustStoreAbsolutePath(), config.trustStorePassword());
    	if (sf == null) {
			logger.error("Failed - process: createInWeboSSLSocketFactory");
    		return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    	}
    	
    	/* If we are doing PUSH action, then inWebo action = pushAuthenticate
    	 * 
    	 * InWebo Endpoint
    	 * 	URL:
    	 * 		https://api.myinwebo.com/FS?action= pushAuthenticate + parameters
    	 * 	Mandatory parameters:
    	 * 		&serviceId= <service id> //integer
    	 * 		&userId=<login of the previsously authenticated user> //string
    	 */
    	if (config.actionSelection().getValue().equals(InWeboAction.PUSH.getValue())) {
    		logger.debug("process: PUSH InWebo");
    		
        	String inWeboResp = null;
        	inWeboResp = callInWebo(sf,config.inWeboURL(), "pushAuthenticate", config.serviceId(), username, null,null);
        	logger.debug("process PUSH: inWeboResp value " + inWeboResp);
    		    			
        	if (inWeboResp == null){
    			logger.error("Failed - process PUSH: callInwebo");
    		    return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
        	}

    		InputSource inputSourceInwebo = new InputSource();
    		inputSourceInwebo.setCharacterStream(new StringReader(inWeboResp));
    		
        	String errInWebo = null;
    		try {
    			docInWebo = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(inputSourceInwebo);
    			errInWebo = docInWebo.getElementsByTagName("err").item(0).getTextContent();
    		} catch (SAXException e) {
    			logger.error("Failed - process PUSH: SAXException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}catch (ParserConfigurationException e) {
    			logger.error("Failed - process PUSH: ParserConfigurationException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		} catch (IOException e) {
    			logger.error("Failed - process PUSH: IOException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}
    		
    		logger.debug("process PUSH: errInwebo " + errInWebo);   
    		
    		if (errInWebo == null || errInWebo.isEmpty()) {
    			logger.error("Failed - process PUSH: No err response from InWebo");
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		} else if (errInWebo.indexOf(":")>0 && errInWebo.subSequence(0,errInWebo.indexOf(":")).equals("NOK")){
    			logger.debug("errInwebo - code: " + errInWebo.subSequence(0,errInWebo.indexOf(":")));
    			logger.debug("errInwebo - message: " + errInWebo.substring(errInWebo.indexOf(":")+1));
    			logger.error("Failed - process PUSH: Error from InWebo");
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}else {
    			logger.debug("errInwebo - code: " + errInWebo);
    			logger.trace("Success - process PUSH: Push initiated at InWebo");
    			logger.trace("====================================== InWebo PUSH Process end ======================================\n");
    			return complete(context.sharedState.copy().
    					put("inWeboSessionId", docInWebo.getElementsByTagName("sessionId").item(0).getTextContent()).
    					put("inWeboAlias",docInWebo.getElementsByTagName("alias").item(0).getTextContent()),
    					InWeboActionNodeOutcome.OK);
    		}
        } 
    	/* If we are doing OTP action, then inWebo action = authenticateExtended
    	 * 
    	 * InWebo Endpoint
    	 * 	URL:
    	 * 		https://api.myinwebo.com/FS?action=authenticateExtended + parameters
    	 * 	Mandatory parameters:
    	 * 		&serviceId= <id of the service> //integer
    	 * 		&userId=<login name> //string
    	 * 		&token=<otp generated> //string
    	 */
    	else if (config.actionSelection().getValue().equals(InWeboAction.OTP.getValue()) && !config.inWeboAction().isEmpty()){
    		logger.trace("process: OTP InWebo");

        	String inWeboResp = null;
        	inWeboResp = callInWebo(sf,config.inWeboURL(), "authenticateExtended", config.serviceId(), username, null,otp);
        	logger.debug("process OTP: inWeboResp value " + inWeboResp);
        	
        	
        	
        	if (inWeboResp == null){
    			logger.error("Failed - process OTP: callInwebo");
    		    return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
        	}
        	

    		InputSource inputSourceInwebo = new InputSource();
    		inputSourceInwebo.setCharacterStream(new StringReader(inWeboResp));
    		
        	String errInWebo = null;
    		
        	try {
    			docInWebo = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(inputSourceInwebo);
    			errInWebo = docInWebo.getElementsByTagName("err").item(0).getTextContent();
    		} catch (SAXException e) {
    			logger.error("Failed - process OTP: SAXException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}catch (ParserConfigurationException e) {
    			logger.error("Failed - process OTP: ParserConfigurationException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		} catch (IOException e) {
    			logger.error("Failed - process OTP: IOException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}
    		
        	
    		logger.debug("process OTP: errInwebo " + errInWebo);    						
    		if (errInWebo == null || errInWebo.isEmpty()) {
    			logger.error("Failed - process OTP: No err response from InWebo");
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		} else if (errInWebo.indexOf(":")>0 && errInWebo.subSequence(0,errInWebo.indexOf(":")).equals("NOK")){
    			logger.debug("errInwebo - code: " + errInWebo.subSequence(0,errInWebo.indexOf(":")));
    			logger.debug("errInwebo - message: " + errInWebo.substring(errInWebo.indexOf(":")+1));
    			logger.error("Failed - process OTP: Error from InWebo");
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}else {
    			logger.debug("errInwebo - code: " + errInWebo);
    			logger.trace("Success - process OTP: OTP validated at InWebo");
    			logger.trace("====================================== InWebo OTP Process end ======================================\n");
    			return complete(context.sharedState.copy().
    					put("inWeboAlias", docInWebo.getElementsByTagName("alias").item(0).getTextContent()).
    					put("inWeboPlatform",docInWebo.getElementsByTagName("platform").item(0).getTextContent()),InWeboActionNodeOutcome.OK);
    		}
        }
    	/* If we are doing the CHECK action, then inWebo action = checkPushResult
    	 * 
    	 * InWebo Endpoint
    	 * 	URL:
    	 * 		https://api.myinwebo.com/FS?action= checkPushResult + parameters
    	 * 	Mandatory parameters:
    	 * 		&serviceId= <service id> //integer
    	 * 		&sessionId=<session id> //string
    	 * 		&userId=<login> //string
    	 */
    	else if(config.actionSelection().getValue().equals(InWeboAction.CHECK.getValue()) && !inWeboSessionId.isEmpty()){
    		logger.trace("process: CHECK InWebo");

        	String inWeboResp = null;
        	inWeboResp = callInWebo(sf,config.inWeboURL(), "checkPushResult", config.serviceId(), username, inWeboSessionId,null);
        	logger.debug("process CHECK: inWeboResp value " + inWeboResp);
        	
        	
        	if (inWeboResp == null){
    			logger.error("Failed - process CHECK: callInwebo");
    		    return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
        	}
        	

    		InputSource inputSourceInwebo = new InputSource();
    		inputSourceInwebo.setCharacterStream(new StringReader(inWeboResp));
    		
        	String errInWebo = null;
    		
        	try {
    			docInWebo = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(inputSourceInwebo);
    			errInWebo = docInWebo.getElementsByTagName("err").item(0).getTextContent();
    		} catch (SAXException e) {
    			logger.error("Failed - process CHECK: SAXException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}catch (ParserConfigurationException e) {
    			logger.error("Failed - process CHECK: ParserConfigurationException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		} catch (IOException e) {
    			logger.error("Failed - process CHECK: IOException " + e.getMessage());
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}
    		
        	
    		logger.debug("process CHECK: errInwebo " + errInWebo);    						
    		if (errInWebo == null || errInWebo.isEmpty()) {
    			logger.error("Failed - process CHECK: No err response from InWebo");
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		} else if (
    				errInWebo.indexOf(":")>0 && 
    				errInWebo.subSequence(0,errInWebo.indexOf(":")).equals("NOK") && 
    				errInWebo.substring(errInWebo.indexOf(":")+1).equals("WAITING")){
    			logger.debug("errInwebo - code: " + errInWebo.subSequence(0,errInWebo.indexOf(":")));
    			logger.debug("errInwebo - message: " + errInWebo.substring(errInWebo.indexOf(":")+1));
    			logger.debug("Waiting - process CHECK: Wait for user action in inWebo");
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.WAIT);
    		} else if (errInWebo.indexOf(":")>0 && errInWebo.subSequence(0,errInWebo.indexOf(":")).equals("NOK")){
    			logger.debug("errInwebo - code: " + errInWebo.subSequence(0,errInWebo.indexOf(":")));
    			logger.debug("errInwebo - message: " + errInWebo.substring(errInWebo.indexOf(":")+1));
    			logger.error("Failed - process CHECK: Error from InWebo");
    			return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
    		}else {
    			logger.debug("errInwebo - code: " + errInWebo);
    			logger.trace("Success - process CHECK: CHECK validated at InWebo");
    			logger.trace("====================================== InWebo CHECK Process end ======================================\n");
    			return complete(context.sharedState.copy().
    					put("inWeboAlias", docInWebo.getElementsByTagName("alias").item(0).getTextContent()).
    					put("inWeboPlatform",docInWebo.getElementsByTagName("platform").item(0).getTextContent()),InWeboActionNodeOutcome.OK);
    		}
        } else if (config.actionSelection().getValue().equals(InWeboAction.OTHER.getValue()) && !config.inWeboAction().isEmpty()){
        	/*
        	 * TODO implement default behavior when the user select OTHER action in the dropdown menu
        	 * @Return ERROR for the time being
        	 */
        	return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
        } else {
            logger.trace("-_-'   -_-'   -_-'   -_-'   -_-'   -_-'   -_-'   -_-'   -_-'   -_-'   -_-'   -_-'   -_-'   ");
            logger.warn("process: No action defined - Check you entered a value for \"InWebo Push Action URL paramater\"");
    		logger.trace("====================================== InWebo Process end ======================================\n");
            return complete(context.sharedState.copy(),InWeboActionNodeOutcome.ERROR);
        }
    }
    
    
    private Action complete(JsonValue sharedState, InWeboActionNodeOutcome outcome) {
        return Action.goTo(outcome.getOutcome().id)
        		.replaceSharedState(sharedState)
        		.build();
    }
    
    private String callInWebo(SSLSocketFactory sf,String inWeboURL, String inWeboAction, String serviceId, String username, String sessionId, String otp){
    	
    	HttpsURLConnection conn = null;
    	BufferedReader br = null;
    	String inWeboResp = "";
    	
		try {
			String strURL = inWeboURL
					+ "?action=" + inWeboAction
					+ "&serviceId=" + serviceId
					+ "&userId=" + URLEncoder.encode(username, "UTF-8");
			strURL += (sessionId == null)? "" : "&sessionId=" + sessionId;
			strURL += (otp == null)? "" : "&token=" + otp;
			
			logger.debug("callInWebo: URL " + strURL);
			
			URL url = new URL(strURL);
		
			conn = (HttpsURLConnection) url.openConnection();
		
			conn.setDoOutput(true);
			conn.setRequestMethod("GET");
			conn.setRequestProperty("Content-Type", "application/json");
			conn.setSSLSocketFactory(sf);

			if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
				logger.error("Failed - process: HTTP error code : " + conn.getResponseCode());
			} else {
    			String output="";	
			
    			br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
			
    			while ((output = br.readLine()) != null) {
    				inWeboResp+=output;
    			}
    		}
			
		} catch (UnsupportedEncodingException e) {
    		logger.error("Failed - callInWebo: UnsupportedEncodingException " + e.getMessage());
		} catch (MalformedURLException e) {
    		logger.error("Failed - callInWebo: MalformedURLException " + e.getMessage());
		} catch (IOException e) {
    		logger.error("Failed - callInWebo: IOException " + e.getMessage());
		} finally {
			if (br != null) {
		        try {
		            br.close();
		        } catch (IOException e) {
            		logger.error("Failed - callInWebo: IOException in finally while closing file" + e.getMessage());
		        }
		    }
		    if (conn != null) {
		        conn.disconnect();
		    }
		}
		return inWeboResp;
    }
    
    private SSLSocketFactory createInWeboSSLSocketFactory(
    			String clientStoreInst, String clientStorePath, char[] clientStorePass) {
//    			String trustStoreInst,  String trustStorePath, char[] trustStorePass) {
    	KeyStore clientStore;
		//KeyStore trustStore;
		try {
			clientStore = KeyStore.getInstance(clientStoreInst);
			clientStore.load(new FileInputStream(clientStorePath), clientStorePass);
	    	logger.trace("createInWeboSSLSocketFactory: clientStore loaded");			    	
	    	KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(clientStore, clientStorePass);
			KeyManager[] kms = kmf.getKeyManagers();
				
			//trustStore = KeyStore.getInstance(trustStoreInst);
			//trustStore.load(new FileInputStream(trustStorePath), trustStorePass);
			logger.trace("createInWeboSSLSocketFactory: trustStore loaded");
			//TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			//tmf.init(trustStore);
			//TrustManager[] tms = tmf.getTrustManagers();
			
			logger.trace("createInWeboSSLSocketFactory: TrustManager created");
			
			SSLContext sslContext = null;
			sslContext = SSLContext.getInstance("TLS");
//			sslContext.init(kms, tms, new SecureRandom());
			sslContext.init(kms, null, new SecureRandom());
			logger.trace("createInWeboSSLSocketFactory: sslContext init");
			
			return sslContext.getSocketFactory();

		} catch (NoSuchAlgorithmException e) {
			logger.error("Failed - createInWeboSSLSocketFactory: NoSuchAlgorithmException " + e.getMessage());
		} catch (CertificateException e) {
			logger.error("Failed - createInWeboSSLSocketFactory: CertificateException " + e.getMessage());
		} catch (KeyStoreException e) {
			logger.error("Failed - createInWeboSSLSocketFactory: KeyStoreException " + e.getMessage());
		} catch (UnrecoverableKeyException e) {
			logger.error("Failed - createInWeboSSLSocketFactory: UnrecoverableKeyException " + e.getMessage());
		} catch (KeyManagementException e) {
			logger.error("Failed - createInWeboSSLSocketFactory: KeyManagementException " + e.getMessage());
		} catch (FileNotFoundException e) {
			logger.error("Failed - createInWeboSSLSocketFactory: FileNotFoundException " + e.getMessage());
		} catch (IOException e) {
			logger.error("Failed - createInWeboSSLSocketFactory: FileNotFoundException " + e.getMessage());
		}
		return null;
    }
    
    public enum InWeboAction {
        /** Push */
        PUSH("PUSH"),
        /** Check */
        CHECK("CHECK"),
        /** OTP */
        OTP("OTP"),
        /** Check */
        OTHER("OTHER");

        private String value;

        /**
         * The constructor.
         * @param value the value as a string.
         */
        InWeboAction(String value) {
            this.value = value;
        }

        /**
         * Gets the action preference value.
         * @return the value.
         */
        public String getValue() {
            return value;
        }
    }
    
    /**
     * The possible outcomes for the PollingWaitNode.
     */
    public enum InWeboActionNodeOutcome {
        /**
         * The user has successfully validated with inWebo.
         */
        OK("Ok"),
        /**
         * inWebo waits for validation from user.
         */
        WAIT("Wait"),
        /**
         * inWebo error occurd.
         */
        ERROR("Error");

        String displayValue;

        /**
         * Constructor.
         * @param displayValue The value which is displayed to the user.
         */
        InWeboActionNodeOutcome(String displayValue) {
            this.displayValue = displayValue;
        }

        private OutcomeProvider.Outcome getOutcome() {
            return new OutcomeProvider.Outcome(name(), displayValue);
        }
    }
    
    /**
     * Provides the outcomes for the polling wait node.
     * */
    public static class InWeboActionNodeOutcomeProvider implements OutcomeProvider {
    	@Override
    	public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
    		List<Outcome> outcomes = new ArrayList<>();
    		outcomes.add(InWeboActionNodeOutcome.OK.getOutcome());
    		outcomes.add(InWeboActionNodeOutcome.ERROR.getOutcome());
    		if (nodeAttributes.isNotNull()) {
    			// nodeAttributes is null when the node is created
    			if (nodeAttributes.get("actionSelection").asString().equals(InWeboAction.CHECK.getValue())) {
    				outcomes.add(InWeboActionNodeOutcome.WAIT.getOutcome());
    			}
    		}
    		return outcomes;
    	}
    }
    
    /**
     * Method to dump a trace of the sharedState
     * @param context
     */
    private void traceDumpShareState (TreeContext context) {
    	logger.trace("====================================== InWebo Push Dump sharedState ======================================\n"
    			+"realm="+context.sharedState.get("realm")
    			+"\n"+"authLevel="+context.sharedState.get("authLevel")
    			+"\n"+"targetAuthLevel="+context.sharedState.get("targetAuthLevel")
    			+"\n"+"currentNodeId="+context.sharedState.get("currentNodeId")
    			+"\n"+"username="+context.sharedState.get("username")
    			+"\n"+"NodeType="+context.sharedState.get("NodeType")
    			+"\n"+"state="+context.sharedState.get("state")
    			+"\n"+"inWeboSessionId="+context.sharedState.get("inWeboSessionId")
    			+"\n"+"inWeboAlias="+context.sharedState.get("inWeboAlias")
    			+"\n"+"inWeboPlatform="+context.sharedState.get("inWeboPlatform")+"\n");

    }
}
