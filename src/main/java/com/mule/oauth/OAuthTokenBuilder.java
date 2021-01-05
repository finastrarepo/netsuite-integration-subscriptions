package com.mule.oauth;
/**
 * gGenerate Oauth 1.0a header for Mulesoft
 * @author kalidass mookkaiah
 * @version 1.0
 * @date 08 April 2020
 * 
 */


import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class to generate Oauth 1.0a header
 */
public class OAuthTokenBuilder {

    private String consumerKey;
    private String consumerSecret;
    private String signatureMethod;
    private String token;
    private String tokenSecret;
    private String version;
    private String realm;
    
    private static final String oauth_consumer_key = "oauth_consumer_key";
    private static final String oauth_token = "oauth_token";
    private static final String oauth_signature_method = "oauth_signature_method";
    private static final String oauth_timestamp = "oauth_timestamp";
    private static final String oauth_nonce = "oauth_nonce";
    private static final String oauth_version = "oauth_version";
    private static final String oauth_signature = "oauth_signature";
    private static final String oauth_realm = "realm";
    //Fixed algorithm, can be made dynamic as well if needed in future
    private static final String HMAC_SHA1 = "HmacSHA1";
    
    //private static final String oauth_realm = "realm";
    
    /**
     * Constructor to initialise the class by passing in key parameter to generate netsuite OAuth token
     * 
     * @param consumerKey
     * @param consumerSecret
     * @param token
     * @param tokenSecret
     */
    public OAuthTokenBuilder(String consumerKey, String consumerSecret, String token, String tokenSecret, String realm) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.token = token;
        this.tokenSecret = tokenSecret;
        this.signatureMethod = "HMAC-SHA1";
        this.version = "1.0";
        this.realm = realm;
    }
    
    /**
     * Generates oAuth 1.0a header which can be pass as Authorization header
     * 
     * @param httpMethod
     * @param url
     * @param requestParams
     * @return
     */
    public String generateHeader(String httpMethod, String url, Map<String, String> requestParams) {
        StringBuilder base = new StringBuilder();
        
        // generate nonce
        String nonce = getNonce();
        
        //generate timestamp
        String timestamp = getTimestamp();
        
        //generate base string
        String baseSignatureString = generateSignatureBaseString(httpMethod, url, requestParams, nonce, timestamp);
        
        //generate HMAC-SHA1 signature
        String signature = encryptUsingHmacSHA1(baseSignatureString);
        
        // generate the token
        base.append("OAuth ");
        append(base, oauth_realm, realm);
        append(base, oauth_consumer_key, consumerKey);
        append(base, oauth_token, token);
        append(base, oauth_signature_method, signatureMethod);
        append(base, oauth_timestamp, timestamp);
        append(base, oauth_nonce, nonce);
        append(base, oauth_version, version);
        append(base, oauth_signature, signature);
        base.deleteCharAt(base.length() - 1);
        //System.out.println("header : " + base.toString());
        
        return base.toString();
    }
    
    
    public String generateHeaderNs(String httpMethod, String url) {
        StringBuilder base = new StringBuilder();
        
        // generate nonce
        String nonce = getNonce();
        
        //generate timestamp
        String timestamp = getTimestamp();
        
        //generate base string
        String baseSignatureString = generateSignatureBaseStringNs(httpMethod, url, nonce, timestamp);
        
        //generate HMAC-SHA1 signature
        String signature = encryptUsingHmacSHA1(baseSignatureString);
        
        // generate the token
        base.append("OAuth ");
        append(base, oauth_realm, realm);
        append(base, oauth_consumer_key, consumerKey);
        append(base, oauth_token, token);
        append(base, oauth_signature_method, signatureMethod);
        append(base, oauth_timestamp, timestamp);
        append(base, oauth_nonce, nonce);
        append(base, oauth_version, version);
        append(base, oauth_signature, signature);
        base.deleteCharAt(base.length() - 1);
        //System.out.println("header : " + base.toString());
        
        return base.toString();
    }
    /**
     * Return a random generated nonce
     * 
     * @param none
     * @return String
     */
    private String getNonce() {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        
        // length of the nonce
        int targetStringLength = 10;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1).filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97)).limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
        return generatedString;

    }

    /**
     * Return a time stamp
     * 
     * @param none
     * @return String
     */
    private String getTimestamp() {
        return Math.round((new Date()).getTime() / 1000.0) + "";
    }
    
    /**
     * Allows to append key value pair to String
     * 
     * @param none
     * @return String
     */
    private void append(StringBuilder builder, String key, String value) {
        // append parameters with = sign
    	builder.append(encode(key)).append("=\"").append(encode(value)).append("\",");
    }
    
    /**
     * Allows to append key value pair to Map
     * 
     * @param none
     * @return String
     */
    private void put(Map<String, String> map, String key, String value) {
        map.put(encode(key), encode(value));
    }
    
    /**
     * Percentage encode String as per RFC 3986, Section 2.1
     * 
     * @param value
     * @return
     */
    private String encode(String value) {
        String encoded = "";
        try {
            encoded = URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        String sb = "";
        char focus;
        
        // take care of special charaters while encoding like * + and % signs
        for (int i = 0; i < encoded.length(); i++) {
            focus = encoded.charAt(i);
            if (focus == '*') {
                sb += "%2A";
            } else if (focus == '+') {
                sb += "%20";
            } else if (focus == '%' && i + 1 < encoded.length() && encoded.charAt(i + 1) == '7' && encoded.charAt(i + 2) == 'E') {
                sb += '~';
                i += 2;
            } else {
                sb += focus;
            }
        }
        return sb.toString();
    }
    
    /**
     * Generate base string to generate the oauth_signature
     * 
     * @param httpMethod
     * @param url
     * @param requestParams
     * @return String
     */
    private String generateSignatureBaseString(String httpMethod, String url, Map<String, String> requestParams, String nonce, String timestamp) {
        Map<String, String> params = new HashMap<>();
        requestParams.entrySet().forEach(entry -> {
            put(params, entry.getKey(), entry.getValue());
        });
        
        // add the OAuth parameters 
        put(params, oauth_consumer_key, consumerKey);
        put(params, oauth_nonce, nonce);
        put(params, oauth_signature_method, signatureMethod);
        put(params, oauth_timestamp, timestamp);
        put(params, oauth_token, token);
        put(params, oauth_version, version);
        
        // sort the parameters by alphabetical order
        Map<String, String> sortedParams = params.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (oldValue, newValue) -> oldValue, LinkedHashMap::new));
        StringBuilder base = new StringBuilder();
        sortedParams.entrySet().forEach(entry -> {
            base.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        });
        
        // remove the last &
        base.deleteCharAt(base.length() - 1);
        
        // append together the Method and url and parameters
        String baseString = httpMethod.toUpperCase() + "&" + encode(url) + "&" + encode(base.toString());
        
        return baseString;
    }
    
    
    private String generateSignatureBaseStringNs(String httpMethod, String url, String nonce, String timestamp) {
        Map<String, String> params = new HashMap<>();
                
        // add the OAuth parameters 
        put(params, oauth_consumer_key, consumerKey);
        put(params, oauth_nonce, nonce);
        put(params, oauth_signature_method, signatureMethod);
        put(params, oauth_timestamp, timestamp);
        put(params, oauth_token, token);
        put(params, oauth_version, version);
        
        // sort the parameters by alphabetical order
        Map<String, String> sortedParams = params.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (oldValue, newValue) -> oldValue, LinkedHashMap::new));
        StringBuilder base = new StringBuilder();
        sortedParams.entrySet().forEach(entry -> {
            base.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        });
        
        // remove the last &
        base.deleteCharAt(base.length() - 1);
        
        // append together the Method and url and parameters
        String baseString = httpMethod.toUpperCase() + "&" + encode(url) + "&" + encode(base.toString());
        
        return baseString;
    }
    /**
     * Generate encrypted HMAC SHA1 response for string
     * 
     * @param String
     * @return String
     */
    private String encryptUsingHmacSHA1(String input) {
        // create the secret key
    	String secret = new StringBuilder().append(encode(consumerSecret)).append("&").append(encode(tokenSecret)).toString();
        
    	// encode the secret using UTF8
    	byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        
    	// generate the HMAC-SHA1 hash
    	SecretKey key = new SecretKeySpec(keyBytes, HMAC_SHA1);
        Mac mac;
        try {
            mac = Mac.getInstance(HMAC_SHA1);
            mac.init(key);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
        
        // convert the HMAC from binary to UTF8 
        byte[] signatureBytes = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        
        //return the base64 encoded signature
        return new String(Base64.getEncoder().encode(signatureBytes));
    }

	/**
	 * @param args
	 */
	/*public static void main(String[] args) {
		
		//Example Auth fields
		String CONSUMER_KEY = "96730b5401fb42b3156780b09b55b7a5c3b16388ada75702194749e14b818741";

		 String CONSUMER_SECRET = "2dd17b3e994d23b610322d3e6e3082819f33b503bc8e38f54bdfc3cdc792edd3";

		 String ACCESS_TOKEN = "fc06e1183e34a8bfdb52f68d32ea1269a990b467536e82a15b8e6d49e1a09c37";

		 String TOKEN_SECRET = "2e954d33727a4fee5652368ea75a3db9dcfb7ab71922ad918339edb9470e3094";
    	
    	// Example Parameters 
    	Map<String, String> requestParams = new HashMap<String, String>();
    	requestParams.put("script", "customscriptzab_api_restlet");
    	requestParams.put("deploy", "customdeployzab_api_restlet");
    	requestParams.put("export_id", "zab_subscription");
    	requestParams.put("internalid", "11");
    	
    	
    	// Initialise the call by passing auth fields 
    	OAuthTokenBuilder tot = new OAuthTokenBuilder(CONSUMER_KEY,CONSUMER_SECRET,ACCESS_TOKEN,TOKEN_SECRET);
    	
    	// generate header by passing NETSUITE CALL GET METHOD and NETSUITE URL and NETSUITE PARAMS
    	String header = tot.generateHeaderNs("GET", "https://3431250-sb99.suitetalk.api.netsuite.com/rest/platform/v1/record/contact/eid:0013M000002Go58QAC" );
    	
    	
    	// Print the headers
    	//System.out.println("Header = ");
    	System.out.println(header);

	}*/

}