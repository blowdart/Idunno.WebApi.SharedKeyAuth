//-----------------------------------------------------------------------
// <copyright file="SharedKeyValidatingHandler.cs" company="Microsoft">
//    Copyright 2012 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Idunno.WebApi.SharedKeyAuthentication
{
    public class SharedKeyValidatingHandler : DelegatingHandler
    {
        /// <summary>
        /// The anonymous principal which is attached if authentication headers are not present.
        /// </summary>
        private static readonly ClaimsPrincipal AnonymousPrincipal = 
            new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> { new Claim(ClaimTypes.Name, string.Empty) }));

        /// <summary>
        /// Initializes a new instance of the <see cref="SharedKeyValidatingHandler" /> class.
        /// </summary>
        public SharedKeyValidatingHandler()
        {            
            this.MaximumMessageAge = new TimeSpan(0, 0, 5, 0);
        }

        /// <summary>
        /// Gets or sets the shared secret resolver.
        /// </summary>
        /// <value>
        /// The shared secret resolver.
        /// </value>
        public Func<string, byte[]> SharedSecretResolver
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the age after which a message will be rejected.
        /// </summary>
        /// <value>
        /// The maximum message age.
        /// </value>
        public TimeSpan MaximumMessageAge
        {
            get; 
            set;
        }

        /// <summary>
        /// Sends an HTTP request to the inner handler to send to the server as an asynchronous operation.
        /// </summary>
        /// <param name="request">The HTTP request message to send to the server.</param>
        /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
        /// <returns>
        /// Returns <see cref="T:System.Threading.Tasks.Task`1" />. The task object representing the asynchronous operation.
        /// </returns>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }
            
            AuthenticationHeaderValue authenticationHeader = null;
            
            if (request.Headers != null)
            {
                authenticationHeader = request.Headers.Authorization;
            }

            string accountName;
            byte[] sentHmac;

            if (request.Headers != null && DateTime.Now - request.Headers.Date > this.MaximumMessageAge)
            {
                return Forbidden("Request Expired");                
            }

            if (authenticationHeader == null || 
                string.IsNullOrWhiteSpace(authenticationHeader.Parameter) || 
                authenticationHeader.Scheme != SharedKeyAuthentication.Scheme || 
                !SharedKeyAuthentication.TryParse(authenticationHeader.Parameter, out accountName, out sentHmac))
            {
                this.AttachPrincipal(AnonymousPrincipal);
            }
            else
            {
                byte[] sharedKey = this.SharedSecretResolver(accountName);

                if (sharedKey == null || sharedKey.Length == 0)
                {
                    // Account not found
                    return Unauthorized();
                }

                // Now check the checksums
                // First, if a body is present, ensure it hasn't changed.
                Task<byte[]> readContent = request.Content.ReadAsByteArrayAsync();
                byte[] requestContent = readContent.Result;
                if (requestContent.Length > 0)
                {
                    var sentHash = request.Content.Headers.ContentMD5;

                    if (sentHash == null)
                    {
                        return Forbidden("Content-MD5 header must be specified when a request body is included.");                                        
                    }

                    using (var md5 = new MD5CryptoServiceProvider())
                    {
                        byte[] computedHash = md5.ComputeHash(requestContent);
                        if (!CompareHash(sentHash, computedHash))
                        {
                            return PreconditionFailed("Content-MD5 does not match the request body.");
                        }
                    }
                }

                // Now check the actual auth signature.
                byte[] calculatedHmac = SharedKeySignature.Calculate(request, accountName, sharedKey);

                if (!CompareHash(sentHmac, calculatedHmac))
                {
                    return Forbidden("Token validation failed.");
                }

                var claims = new List<Claim> { new Claim(ClaimTypes.Name, accountName) };
                var claimsIdentity = new ClaimsIdentity(claims, SharedKeyAuthentication.Scheme);
                var claimsPrinciple = new ClaimsPrincipal(claimsIdentity);
                this.AttachPrincipal(claimsPrinciple);
            }

            return base.SendAsync(request, cancellationToken);
        }

        /// <summary>
        /// Attaches the specified principal to the current thread and HTTP Context if one exists.
        /// </summary>
        /// <param name="principal">The principal to attach..</param>
        protected virtual void AttachPrincipal(ClaimsPrincipal principal)
        {
            Thread.CurrentPrincipal = principal;
            if (HttpContext.Current != null)
            {
                HttpContext.Current.User = principal;
            }
        }

        /// <summary>
        /// Returns an unauthorized response.
        /// </summary>
        /// <returns>An unauthorized response.</returns>
        private static Task<HttpResponseMessage> Unauthorized()
        {
            return Task<HttpResponseMessage>.Factory.StartNew(() => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        }

        /// <summary>
        /// Returns a forbidden response, with the specified reason.
        /// </summary>
        /// <param name="reason">The reason the request is unauthorized.</param>
        /// <returns>A forbidden response.</returns>
        private static Task<HttpResponseMessage> Forbidden(string reason)
        {
            return Task<HttpResponseMessage>.Factory.StartNew(() => new HttpResponseMessage(HttpStatusCode.Forbidden) { ReasonPhrase = reason });
        }

        /// <summary>
        /// Returns a precondition failed response, with the specified reason.
        /// </summary>
        /// <param name="reason">The reason the request is unauthorized.</param>
        /// <returns>A precondition failed response.</returns>
        private static Task<HttpResponseMessage> PreconditionFailed(string reason)
        {
            return Task<HttpResponseMessage>.Factory.StartNew(() => new HttpResponseMessage(HttpStatusCode.PreconditionFailed) { ReasonPhrase = reason });
        }

        /// <summary>
        /// Compares two hashes in a time consistent manner.
        /// </summary>
        /// <param name="left">The first has to compare.</param>
        /// <param name="right">The second has to compare.</param>
        /// <returns>True if the hashes are identical, otherwise false.</returns>
        [MethodImpl(MethodImplOptions.NoOptimization)]
        private static bool CompareHash(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            var result = true;
            for (var i = 0; i < left.Length; i++)
            {
                result = result & (left[i] == right[i]);
            }

            return result;
        }
    }
}
