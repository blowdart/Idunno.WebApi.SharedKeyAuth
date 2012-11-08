Idunno.WebApi.SharedKeyAuth
===========================

Example ASP.NET WebApi authentication attribute and infrastructure for shared key authentication.

Features
--------
- WebAPI Message Handler based for both client and server code
- Uses the same RESTFUL authentication scheme as Azure Blob and Queue Services (v2009-09-19)
- Timestamping to prevent replay attacks, with configurable validity periods.
- Easily configurable api account to shared secret lookup resolver.
- Creates and attaches a `ClaimsPrinciple` so webapi `[Authorize]` and the `User` property work as expected.

Usage Examples
--------------

### Client ###

Create an HttpClient with a `SharedKeySigningHandler', passing in the account name and shared secret
issued by the receiving site.

    var client = new HttpClient(new SharedKeySigningHandler(accountName, secretSecret));
    var response = client.PostAsJsonAsync("http://contoso.com/api/Resources", resource).Result;

### Server ###

Wire up the `SharedKeyValidatingHandler` to your API, for example to apply globally you
could put the following in your `Application_Start()`

    GlobalConfiguration.Configuration.MessageHandlers
        .Add(new SharedKeyValidatingHandler()
                 {
                     SharedSecretResolver = ExampleSharedSecretLookup.Lookup
                 });

A `SharedSecretResolver` can be any method which takes an account identifier as a string, and returns
a byte array containing the shared secret; for example
   
    public static class ExampleSharedSecretLookup
    {        
        private static readonly Dictionary<string, byte[]> Secrets = 
            new Dictionary<string, byte[]>
            {
                { 
                    "barryd", 
                    Convert.FromBase64String("KUreulZKB1y//AIuXQInef7X66LRWbeCIJyQyMH33sbkmuFwk7Z+U7/iTj9MNFY/ynaHg5NenUbJKfxWLLNVsw==") 
                 } 
            };

        public static byte[] Lookup(string accountName)
        {
            return !Secrets.ContainsKey(accountName) ? null : Secrets[accountName];
        }
    }



Resources
---------
- [Azure REST Authentication Schemes](http://msdn.microsoft.com/en-us/library/windowsazure/dd179428.aspx)