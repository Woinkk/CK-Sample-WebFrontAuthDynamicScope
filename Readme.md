# CK-WebFrontAuth-DynamicScope

This sample shows you a way to use the dynamic scope provider from the package CK-DB-AspNet-Auth.

## Installation
Please install these before running the project :
- SQL Server (2017 or +)
- Node
- Npm

## <p id="setup">Setup</p>
You will need to create a [Google OAuth App](https://console.cloud.google.com/apis/credentials) and [Facebook OAuth App](https://developers.facebook.com/apps)

### Google OAuth App
---
To create a Google OAuth App, please follow the link above in the [setup section](#setup), you will land on Google Cloud Plateform, from there you will need to create a new project.

You will now be able to create credentials for your application which will provide you a client id and client secret, please follow the next steps :
- First you will need to configure OAuth consent screen [here](https://console.cloud.google.com/apis/credentials/consent) this is separate in 4 steps :
  - OAuth consent screen

    Nothing much to do here just fill the informations with yours.

  - Scopes
    
    In this step you'll need to add the scope "openid" then you can move on the next step.

  - Optional info
    
    Nothing to do here.

  - Summary
    
    When at this step you can now save and go back to credentials.

- On the credentials page you can now click on create credentials and select OAuth client ID
  - In the "Authorized redirect URIs" section add your redirect URI.
  
From there you you will be able to get your client ID and client secret to fill your appsettings.json with those informations.

### Facebook OAuth App
---
To create a Facebook OAuth App, please follow the link above in the [setup section](#setup), from there you will need to create a new project of type none.

And... Nothing else, you can now copy and past your client id and client secret and you're ready to go !

---

Once your appsettings.json is properly set you can now feel free to test whatever you want on this sample !