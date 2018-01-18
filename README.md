# XNAT OpenID Authentication Provider Plugin #


## Building ##

To build the XNAT OpenID authentication provider plugin:

1. If you haven't already, clone [this repository](https://github.com/qcif/xnat-openid-auth-plugin.git) and cd to the newly cloned folder.

1. Build the plugin:

    `./gradlew clean jar distZip` 
    
    On Windows, you can use the batch file:
    
    `gradlew.bat clean jar distZip`
    
    This should build the plugin in the file **build/libs/xnat-openid-auth-plugin-1.0.0-SNAPSHOT.jar** 
    (the version may differ based on updates to the code).
    
1. Copy the plugin jar to your plugins folder: 

    `cp build/libs/xnat-xnat-openid-auth-plugin-1.0.0-SNAPSHOT.jar /data/xnat/home/plugins`

## Configuring and Testing ##

XNAT searches for authenticatin server configurations by looking for files whose names match the pattern:

    *-provider.properties
    
It looks in the following locations:

* On the classpath in the folder **META-INF/xnat/auth**
* In a folder named **auth** under the XNAT home folder (usually configured with the **xnat.home** system variable)

This plugin will use any entries located in any of those properties files where the property **type** is set to "openid". See the sample properties in the resources directory.

## Deploying ##

Deploying your XNAT plugin requires the following steps:

1. Copy the plugin jar to the **plugins** folder for your XNAT installation. The location of the 
**plugins** folder varies based on how and where you have installed your XNAT. If you are running 
a virtual machine created through the [XNAT Vagrant project](https://bitbucket/xnatdev/xnat-vagrant.git),
you can copy the plugin to the appropriate configuration folder and then copy it within the VM from 
**/vagrant** to **/data/xnat/home/plugins**.

1. Restart the Tomcat server. Your new plugin will be available as soon as the restart and initialization process is completed.


