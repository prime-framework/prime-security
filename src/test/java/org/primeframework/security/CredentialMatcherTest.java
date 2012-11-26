/*
 * Copyright (c) 2012, Inversoft Inc., All Rights Reserved
 */
package org.primeframework.security;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.SimpleByteSource;
import org.primeframework.security.shiro.ShiroPrimeAuthenticationToken;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * @author James Humphrey
 */
@Test(groups = "unit")
public class CredentialMatcherTest {

  @Test
  public void match() {

    // configure the matcher
    int hashIterations = 1;
    String algorithm = "MD5";
    HashedCredentialsMatcher matcher = new HashedCredentialsMatcher(algorithm);
    matcher.setHashIterations(hashIterations);
    matcher.setStoredCredentialsHexEncoded(false);

    // uxJ2oHsPCEQD8/GUebOCIg==
    //
    // I flipped the password with the salt (and added curly braces to the salt) to test creating base64 encoded values
    // against jcat's security salting mechanism.
    String password = "Pazwurd1";
    String salt = "{Inversoft}";
    ByteSource saltSource = new SimpleByteSource(password);
    SimpleHash hash = new SimpleHash(algorithm, salt, saltSource, hashIterations);

    // encode it to hex
    String base64EncodedPassword = hash.toBase64();

    // auth info represents the 'actual' information stored on the user
    AuthenticationInfo authInfo = new SimpleAuthenticationInfo("admin@inversoft.com", base64EncodedPassword, saltSource, "test");

    // auth token represents the information entered via a login form
    AuthenticationToken authToken = new ShiroPrimeAuthenticationToken("admin@inversoft.com", salt);

    // now match the auth info to the auto token.  These should match
    assertTrue(matcher.doCredentialsMatch(authToken, authInfo));
  }
}