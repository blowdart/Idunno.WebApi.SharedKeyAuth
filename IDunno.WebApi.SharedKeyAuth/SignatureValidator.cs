//-----------------------------------------------------------------------
// <copyright file="SharedKeyValidator.cs" company="Microsoft">
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
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Idunno.WebApi.SharedKeyAuthentication
{
    internal static class SignatureValidator
    {
        /// <summary>
        /// The anonymous principal which is attached if authentication headers are not present.
        /// </summary>
        private static readonly ClaimsPrincipal AnonymousPrincipal = 
            new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> { new Claim(ClaimTypes.Name, string.Empty) }));

        /// <summary>
        /// Calculates the MD5 checksum of a <paramref name="request"/> body.
        /// </summary>
        /// <param name="request">The <see cref="HttpRequestMessage"/> for which to calculate a checksum.</param>
        /// <returns>The hash value for the <paramref name="request"/> body.</returns>
        public static async Task<byte[]> CalculateBodyMd5(HttpRequestMessage request)
        {
            await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
            using (var bodyStream = new MemoryStream())
            {
                await request.Content.CopyToAsync(bodyStream).ConfigureAwait(false);
                bodyStream.Position = 0;
                if (bodyStream.Length <= 0)
                {
                    return null;
                }

                using (var md5 = new MD5CryptoServiceProvider())
                {
                    return md5.ComputeHash(bodyStream);
                }
            }            
        }

        /// <summary>
        /// Validates the specified request.
        /// </summary>
        /// <param name="request">The <see cref="HttpRequestMessage"/> to validate</param>
        /// <param name="resolver">An account name to shared secret resolver.</param>
        /// <param name="maxAge">The maximum age of a message that will be accepted</param>
        /// <returns>A ClaimsPrincipal for the the identity which owns the message.</returns>
        public static ClaimsPrincipal Validate(HttpRequestMessage request, Func<string, byte[]> resolver, TimeSpan maxAge)
        {
            AuthenticationHeaderValue authenticationHeader = null;
            
            if (request.Headers != null)
            {
                authenticationHeader = request.Headers.Authorization;
            }

            string accountName;
            byte[] sentHmac;

            if (request.Headers != null && DateTime.Now - request.Headers.Date > maxAge)
            {
                throw new ForbiddenException("Request expired.");        
            }

            if (authenticationHeader == null ||
                string.IsNullOrWhiteSpace(authenticationHeader.Parameter) ||
                authenticationHeader.Scheme != SharedKeyAuthentication.Scheme ||
                !SharedKeyAuthentication.TryParse(authenticationHeader.Parameter, out accountName, out sentHmac))
            {
                return AnonymousPrincipal;
            }

            byte[] sharedKey = resolver(accountName);

            if (sharedKey == null || sharedKey.Length == 0)
            {
                // Account not found
                throw new UnauthorizedException();
            }

            if (request.Headers.TransferEncodingChunked == null || !(bool)request.Headers.TransferEncodingChunked)
            {
                if (request.Content.Headers.ContentLength != null && (long)request.Content.Headers.ContentLength > 0)
                {
                    var sentHash = request.Content.Headers.ContentMD5;

                    if (sentHash == null)
                    {
                        throw new ForbiddenException(
                            "Content-MD5 header must be specified when a request body is included.");
                    }

                    if (!CompareHash(sentHash, SignatureValidator.CalculateBodyMd5(request).Result))
                    {
                        throw new PreconditionFailedException("Content-MD5 does not match the request body.");
                    }
                }
            }

            // Now check the actual auth signature.
            byte[] calculatedHmac = SharedKeySignature.Calculate(request, accountName, sharedKey);

            if (!CompareHash(sentHmac, calculatedHmac))
            {
                throw new ForbiddenException("Token validation failed.");
            }

            var claims = new List<Claim> { new Claim(ClaimTypes.Name, accountName) };
            var claimsIdentity = new ClaimsIdentity(claims, SharedKeyAuthentication.Scheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            return claimsPrincipal;
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
