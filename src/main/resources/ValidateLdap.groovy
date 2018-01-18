@Grapes([@Grab("org.springframework.security:spring-security-ldap:4.2.3.RELEASE"), @Grab("org.slf4j:slf4j-nop:1.7.25")])

import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.ldap.DefaultSpringSecurityContextSource
import org.springframework.security.ldap.authentication.BindAuthenticator
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch

String propertiesFile = this.args.length == 0 ? "ldap.properties" : this.args[0].endsWith(".properties") ? this.args[0] : "${this.args[0]}.properties"

final Properties properties = new Properties()
def file = new File(propertiesFile)
if (file.exists()) {
    println "Loading properties from ${file.path}"
    file.withInputStream {
        properties.load it
    }
} else {
    println "No properties file found, using default values"
}

def address = properties.getProperty "address", "ldap://ldap.xnat.org"
def userDn = properties.getProperty "userdn", "cn=admin,dc=xnat,dc=org"
def bindingPassword = properties.getProperty "password", "password"
def searchBase = properties.getProperty "search.base", "ou=users,dc=xnat,dc=org"
def searchFilter = properties.getProperty "search.filter", "(uid={0})"
def username = properties.getProperty "user", "asmith"
def password = properties.getProperty "pass", "password"

println ""
println "address:       ${address}"
println "userdn:        ${userDn}"
println "password:      ${bindingPassword}"
println "search.base:   ${searchBase}"
println "search.filter: ${searchFilter}"
println "user:          ${username}"
println "pass:          ${password}"
println ""

final def contextSource = new DefaultSpringSecurityContextSource(address)
contextSource.setUserDn userDn
contextSource.setPassword bindingPassword
contextSource.afterPropertiesSet()

def atoms = userDn.split ",", 2

println "Validating the binding user account"
def bindingSearchBase = atoms.length > 1 ? atoms[1] : ""
def bindingUsername = atoms[0]
def bindingUserAuthenticated = BindAndAuthenticate(contextSource, bindingSearchBase, "(${ bindingUsername})", bindingUsername, bindingPassword)

if (bindingUserAuthenticated) {
    println "Binding user authenticated successfully, validating the user account ${username}"
    BindAndAuthenticate(contextSource, searchBase, searchFilter, username, password)
}

private boolean BindAndAuthenticate(DefaultSpringSecurityContextSource contextSource, String searchBase, String searchFilter, username, String password) {
    def ldapBindAuthenticator = new BindAuthenticator(contextSource)
    ldapBindAuthenticator.setUserSearch new FilterBasedLdapUserSearch(searchBase, searchFilter, contextSource)

    def provider = new LdapAuthenticationProvider(ldapBindAuthenticator)

    try {
        final Authentication authentication = provider.authenticate new UsernamePasswordAuthenticationToken(username, password)
        println "User ${authentication.principal.username} authentication state: ${authentication.authenticated}"
        authentication.authenticated
    } catch (BadCredentialsException ignored) {
        println "Bad credentials for user ${username}"
        false
    } catch (UsernameNotFoundException ignored) {
        println "Couldn't find user ${username}"
        false
    } catch (AuthenticationException exception) {
        println "Some kind of authentication exception occurred for user ${username}:"
        println "${exception.class.name}: ${exception.message}"
        false
    }
}
