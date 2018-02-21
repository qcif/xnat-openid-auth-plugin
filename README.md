# XNAT OpenID Connect Authentication Provider Plugin #

Tested with [Google's OpenID Connect](https://developers.google.com/identity/protocols/OpenIDConnect "Google OpenID Connect") and [AAF](https://aaf.edu.au/ "AAF")

## Pre-requisities ##

This plugin requires updates in the XDAT and Xnat-web code, using branch `auth-provider-refactor` tagged with the version `1.7.5-auth-B1`. 

1. Clone the [XDAT project](https://bitbucket.org/xnatdev/xdat), then checkout the version specified above.

1. Build the project using the instructions provided.

1. Clone the [XNAT-web project](https://bitbucket.org/qcifltd/xnat-web), then checkout the version specified above.

1. Build the project using the instructions provided or simply `./gradlew clean war`

1. Deploy the resulting war file at `build/libs/` into your Tomcat application. 

## Building ##

To build the XNAT OpenID authentication provider plugin:

1. If you haven't already, clone [this repository](https://github.com/qcif/xnat-openid-auth-plugin.git) and cd to the newly cloned folder.

1. Build the plugin:

    `./gradlew clean fatJar distZip` 
    
    On Windows, you can use the batch file:
    
    `gradlew.bat clean fatJar distZip`
    
This should build the plugin in the file **build/libs/xnat-openid-auth-plugin-1.0.0-SNAPSHOT.jar** (the version may differ based on updates to the code).

## Deploying ##

For more information, please [XNAT documentation on how to deploy plugins.](https://wiki.xnat.org/documentation/xnat-administration/deploying-plugins-in-xnat)

1. Copy the plugin jar to your plugins folder: 

    `cp build/libs/xnat-openid-auth-plugin-all-1.0.0-SNAPSHOT.jar /data/xnat/home/plugins`

1. Copy [Spring JWT library](http://central.maven.org/maven2/org/springframework/security/spring-security-jwt/1.0.8.RELEASE/spring-security-jwt-1.0.8.RELEASE.jar) into the plugins directory:

	`wget http://central.maven.org/maven2/org/springframework/security/spring-security-jwt/1.0.8.RELEASE/spring-security-jwt-1.0.8.RELEASE.jar`

## Configuring and Testing ##

XNAT searches for authenticatin server configurations by looking for files whose names match the pattern:

    *-provider.properties
    
It looks in the following locations:

* On the classpath in the folder **META-INF/xnat/auth**
* In a folder named **auth** under the XNAT home folder (usually configured with the **xnat.home** system variable)

This plugin will use any entries located in any of those properties files where the property **type** is set to "openid". See the sample properties in the resources directory.

The following properties control the plugin:

### enabled
Comma delimited list of provide ids, currently tested with Google `google` and AAF `aaf`.

### siteUrl
The main domain, needed to build the full `preEstablishedRedirUri`

### preEstablishedRedirUri
The return leg of OpenID request after the provider has authenticated, defaults to `<siteUrl>/openid-login`

### openid.`providerId`.clientId
The ID obtained on app registration

### openid.`providerId`.clientSecret
The Secret obtained on app registration

### openid.`providerId`.scopes
Controls the scopes returned by the server: `openid,profile,email`

### openid.`providerId`.link
Controls the link HTML snippet displayed on the Login page for this provider. Location of the link text can optionally be customised by modifying `Login.vm`.

### openid.`providerId`.shouldFilterEmailDomains
Controls whether domains of the email should be compared against the whitelist: `allowedEmailDomains`.

### openid.`providerId`.allowedEmailDomains
Comma delimted whitelist of domains.

### openid.`providerId`.forceUserCreate
Allows skipping of user creation, usually set to true.

### openid.`providerId`.userAutoEnabled
Flag to set the `enabled` property of new users, set to false to allow admins to manually enable users before allowing logins, set to true to allow immediate access.

### openid.`providerId`.userAutoVerified
Flag to set the `verified` property of new users.


## Sample Configuration ##

[Sample configuration files are found here.](src/main/resources/) Please note the need to rename these files before usage, see opening section of the file. 
