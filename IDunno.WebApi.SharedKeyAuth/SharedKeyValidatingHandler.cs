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

            try
            {
                var principal = SignatureValidator.Validate(request, SharedSecretResolver, MaximumMessageAge);
                SetPrincipal(principal);
            }
            catch (UnauthorizedException)
            {
                return Unauthorized();
            }
            catch (ForbiddenException fbex)
            {
                return Forbidden(fbex.Message);
            }
            catch (PreconditionFailedException pcex)
            {
                return PreconditionFailed(pcex.Message);
            }
            
            return base.SendAsync(request, cancellationToken);
        }

        /// <summary>
        /// Attaches the specified principal to the current thread and HTTP Context if one exists.
        /// </summary>
        /// <param name="principal">The principal to attach..</param>
        protected virtual void SetPrincipal(ClaimsPrincipal principal)
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
    }
}
