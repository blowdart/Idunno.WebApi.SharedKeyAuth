//-----------------------------------------------------------------------
// <copyright file="SharedKeySigningHander.cs" company="Microsoft">
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
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Idunno.WebApi.SharedKeyAuthentication
{
    public class SharedKeySigningHandler : DelegatingHandler
    {
        /// <summary>
        /// The account name whose secret will sign the request message.
        /// </summary>
        private readonly string accountName;

        /// <summary>
        /// The shared secret to use when signing the request message.
        /// </summary>
        private readonly byte[] sharedSecret;

        /// <summary>
        /// Initializes a new instance of the <see cref="SharedKeySigningHandler" /> class.
        /// </summary>
        /// <param name="accountName">Name of the account whose secret will sign the message.</param>
        /// <param name="sharedSecret">The secret used to sign the message.</param>
        public SharedKeySigningHandler(string accountName, string sharedSecret) : this(accountName, Convert.FromBase64String(sharedSecret))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SharedKeySigningHandler" /> class.
        /// </summary>
        /// <param name="accountName">Name of the account whose secret will sign the message.</param>
        /// <param name="sharedSecret">The secret used to sign the message.</param>
        public SharedKeySigningHandler(string accountName, byte[] sharedSecret)
        {
            this.InnerHandler = new HttpClientHandler();
            this.accountName = accountName;
            this.sharedSecret = sharedSecret;
        }

        /// <summary>
        /// Sends an HTTP request to the inner handler to send to the server as an asynchronous operation.
        /// </summary>
        /// <param name="request">The HTTP request message to send to the server.</param>
        /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
        /// <returns>
        /// Returns <see cref="T:System.Threading.Tasks.Task`1" />. The task object representing the asynchronous operation.
        /// </returns>
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            if (request.Headers.Date == null)
            {
                request.Headers.Date = DateTime.UtcNow;
            }

            // Check if we have request content, if we do then we need to add a Content-MD5 header.
            if (request.Content != null && request.Content.Headers.ContentMD5 == null)
            {
                await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
                using (var bodyStream = new MemoryStream())
                {
                    await request.Content.CopyToAsync(bodyStream).ConfigureAwait(false);
                    bodyStream.Position = 0;
                    using (var md5 = new MD5CryptoServiceProvider())
                    {
                        request.Content.Headers.ContentMD5 = md5.ComputeHash(bodyStream);
                    }
                }
            }

            byte[] hash = SharedKeySignature.Calculate(request, this.accountName, this.sharedSecret);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                SharedKeyAuthentication.Scheme,
                string.Format(CultureInfo.InvariantCulture, "{0}:{1}", this.accountName, Convert.ToBase64String(hash)));

            // And finally hand off the request to the InnerHandler.
            return await base.SendAsync(request, cancellationToken);
        }
    }
}
