# IDunno.WebApi.SharedKeyAuth #

Example ASP.NET WebApi authentication attribute and infrastructure for shared key authentication.

## Features ##

- Uses the same authentication scheme as Azure Blob and Queue Services (v2009-09-19)
- Authorization specified via the Authorization header.
- Timestamping to prevent replay attacks.
- Configurable api key to shared secret lookup resolver.

## Resources ##

- [Azure REST Authentication Schemes](http://msdn.microsoft.com/en-us/library/windowsazure/dd179428.aspx)
