[![Maven Central](https://maven-badges.herokuapp.com/maven-central/de.svenkubiak/ninja-authentication-module/badge.svg)](https://maven-badges.herokuapp.com/maven-central/de.svenkubiak/ninja-authentication-module)
[![Build Status](https://secure.travis-ci.org/svenkubiak/ninja-authentication.png?branch=master)](http://travis-ci.org/svenkubiak/ninja-authentication)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/4076/badge.svg)](https://scan.coverity.com/projects/4076)

If this software is useful to you, you can support further development by using Flattr. Thank you!

[![Flattr this repository](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=svenkubiak&url=https://github.com/svenkubiak/ninja-authentication&title=ninja-authentication&language=en&tags=github&category=software)


Authentication module for Ninja framework
=====================
This is an easly plugable module for the Ninja web framework to enable authentication services.

Requirements
------------------

Requires [Java SDK 1.8+][1]

Usage
-----

**Please note: This module does not do the actual authentication (checking username and password against store values). It also does not provide any templates for login, registration, etc. It just makes handling authentications in the Ninja web framework a little easier.**

The module mainly consists of two classes: AuthenticationFilter and Authentications.

*AuthenticationFilter*

The AuthenticationFilter is responsible for checking if a user is logged in. It does this by checking if a username is stored in the current session or in a cookie. If no username is found in neither the session or the cookie it will redirect the current request to a predefined url in your application.conf

	auth.redirect.url=/my/login/url
	
If this property is not configured, the filter will return a 403 forbidden.

*Authentications*

The Authentications class offers convenient functions to perform authentication. The main methods are

	getAuthenticationedUser(Context context)
	login(Context context, String username, boolean remember)
	logout(Context context)

Check the JavaDoc for a detailed explanation of the methods.


[1]: http://www.oracle.com/technetwork/java/javase/downloads/index.html