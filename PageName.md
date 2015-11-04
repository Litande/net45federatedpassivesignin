# Introduction #

With .NET 4.5 and WIF fully integrated into the Base Class Library, lot of people found it disappointing to see that the **wif:FederatedPassiveSignIn** ASP.NET control has been removed from the toolkit.

This means that the possibility to easily integrate **multiple** identity providers in one RP application is now gone.

This project aims to recreate the basic functionality of the forementioned control so that its pros are back on .NET 4.5.

# Details #

The source code contains a single class, **CommunityFederatedPassiveSignIn**. The basic usage would be

```
<%@ Register 
    TagPrefix="community" 
    Assembly="Community.IdentityModel.Web" 
    Namespace="Community.IdentityModel.Web.Controls" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
        <div>
            <community:CommunityFederatedPassiveSignIn
                ID="WSFederationLogin"
                runat="server"
                Realm="http://localhost:56118/LoginPage.aspx"
                Issuer="http://localhost:56117/Default.aspx">
            </community:CommunityFederatedPassiveSignIn>
            <asp:Button ID="Another" Text="foo" runat="server" />
        </div>
    </form>
</body>
</html>
```

Currently only three properties are supported and match the original specification:
  * **AutoSignIn**
  * **Realm**
  * **Issuer**