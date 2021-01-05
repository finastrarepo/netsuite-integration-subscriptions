package com.mule.oauth;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.RandomStringUtils;


public class OAuthTokenBuilderHash {

	/*String account;
	String consumerKey;
	String consumerSecret;
	String token;
	String tokenSecret;
	String nonce;
	Long timeStamp;
	String signatureAlgorithm;
	String baseSignatureString;
	String key;*/
	
	/**
	 * 
	 * @param baseString
	 * @param key
	 * @param algorithm
	 * @return result
	 */
	
	public OAuthTokenBuilderHash() {
		
	}
	
	
	public  String computeShaHash(String baseString, String key, String algorithm) {
		 byte[] bytes = key.getBytes(); 
		 SecretKeySpec mySigningKey = new SecretKeySpec(bytes, algorithm);
		      Mac messageAuthenticationCode = null;
			try {
				messageAuthenticationCode = Mac.getInstance(algorithm);
			} catch (NoSuchAlgorithmException e) {
				
				e.printStackTrace();
			}
		      try {
				messageAuthenticationCode.init(mySigningKey);
			} catch (InvalidKeyException e) {
				
				e.printStackTrace();
			}
		      byte[] hash = messageAuthenticationCode.doFinal(baseString.getBytes());
		     /* String result = new String(Base64.encodeBase64(hash, false));*/
		      String result = new String(Base64.getEncoder().encode(hash));
		      return result; 		
	}
	
	/**
	 * 
	 * @param account
	 * @param consumerKey
	 * @param consumerSecret
	 * @param token
	 * @param tokenSecret
	 * @param nonce
	 * @param timeStamp
	 * @param signatureAlgorithm
	 * @return  Signature
	 * @throws Exception
	 */
	
	/*
	 *  Called this method from Mule with (account,consumerKey,consumerSecret,token,tokenSecret)
	 *  Parameters 
	 *  
	 *  No need to send Parameters Like nonce and timeStamp , signatureAlgorithm(hard coded) because it is auto generated
	 */
	
	
	public  String computeSignature(String account,
			String consumerKey, String consumerSecret,String token,String tokenSecret) throws Exception{
		
		String  signatureAlgorithm = "HmacSHA256";
		 
		//Generating Nonce
		String nonce = RandomStringUtils.randomAlphanumeric(20);
				
		//Generating TimeStamp
	    Long timeStamp = System.currentTimeMillis() / 1000L;
		
		// Generating Base String 
		StringBuilder baseString = new StringBuilder();
		baseString.append(account).append("&").append(consumerKey).append("&").append(token).append("&").append(nonce).append("&").append(timeStamp);
		String baseSignatureString = baseString.toString();
		
		// Generating Key 
		StringBuilder key = new StringBuilder();
		key.append(consumerSecret).append("&").append(tokenSecret);
		String keyString = key.toString();
				
		//Get Signature , calling computeShaHash() method
	   String  signature = computeShaHash(baseSignatureString, keyString, signatureAlgorithm);   
	   
	   StringBuilder tokenPassport = new StringBuilder();
	   tokenPassport.append(nonce).append(",").append(timeStamp).append(",")
	   .append(signature).append(",")
	   .append(signatureAlgorithm);	 	   
				return tokenPassport.toString();		
	}
		
	/*public static void main(String[] args) {
		
		String account = "3431250_SB99";
		
		String consumerKey = "96730b5401fb42b3156780b09b55b7a5c3b16388ada75702194749e14b818741";
		
		String consumerSecret = "2dd17b3e994d23b610322d3e6e3082819f33b503bc8e38f54bdfc3cdc792edd3";
		
		String token = "fc06e1183e34a8bfdb52f68d32ea1269a990b467536e82a15b8e6d49e1a09c37";
		
		String tokenSecret = "2e954d33727a4fee5652368ea75a3db9dcfb7ab71922ad918339edb9470e3094";
		
		String signatureAlgorithm = "HmacSHA256";
		
		String nonce = RandomStringUtils.randomAlphanumeric(20);
		
		//System.out.println("nonce---->>>>"+ nonce);
		
		Long timeStamp = System.currentTimeMillis() / 1000L;
		//System.out.println("timeStamp-->>>"+timeStamp);
		
		OAuthTokenBuilderHash test = new OAuthTokenBuilderHash();
		try {
			
			String res =test.computeSignature(account, consumerKey, consumerSecret, token, tokenSecret);
			
			System.out.println("oauth_signature:---->"+res);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		 
	}*/
}