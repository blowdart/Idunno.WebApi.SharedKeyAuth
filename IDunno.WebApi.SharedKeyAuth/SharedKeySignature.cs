//-----------------------------------------------------------------------
// <copyright file="SharedKeySignature.cs" company="Microsoft">
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
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Idunno.WebApi.SharedKeyAuthentication
{
    /// <summary>
    /// Utility class for calculating hashes of messages.
    /// </summary>
    internal static class SharedKeySignature
    {
        /// <summary>
        /// Calculates a SHA256 HMAC for the <seealso cref="request"/>.
        /// </summary>
        /// <param name="request">The request to calculate a hash for.</param>
        /// <param name="accountName">The account name used to access the resource.</param>
        /// <param name="key">The shared secret used to sign the request.</param>
        /// <returns>A SHA256 HMAC of the canonicalized request.</returns>
        internal static byte[] Calculate(HttpRequestMessage request, string accountName, byte[] key)
        {
            var pathQuery = request.RequestUri.PathAndQuery.Split('?');
            string path = pathQuery[0];

            NameValueCollection queryString = pathQuery.Length != 1 ? HttpUtility.ParseQueryString(pathQuery[1]) : new NameValueCollection();

            var canonicalizedRequest = CanonicalizeHttpHeaders(request.Method, request.Headers, request.Content.Headers)
                                       + CanonicalizeCustomHeaders(ConvertToNameValueCollection(request.Content.Headers))
                                       + CanonicalizeResource(path, queryString, accountName);

            return CalculateHmac256(key, canonicalizedRequest);
        }

        /// <summary>
        /// Calculates a SHA256 HMAC for the plain text, using the specified key.
        /// </summary>
        /// <param name="key">The key to use in the HMAC.</param>
        /// <param name="plainText">The plain text to calculate the HMAC for</param>
        /// <returns>A SHA256 HMAC</returns>
        private static byte[] CalculateHmac256(byte[] key, string plainText)
        {
            using (HashAlgorithm hashAlgorithm = new HMACSHA256(key))
            {
                byte[] messageBuffer = Encoding.UTF8.GetBytes(plainText);
                return hashAlgorithm.ComputeHash(messageBuffer);
            }
        }

        /// <summary>
        /// Canonicalizes the HTTP headers.
        /// </summary>
        /// <param name="method">The HTTP method for the request.</param>
        /// <param name="requestHeaders">The request headers.</param>
        /// <param name="contentHeaders">The content headers.</param>
        /// <returns>A string representation of the HTTP headers.</returns>
        private static string CanonicalizeHttpHeaders(
            HttpMethod method,
            HttpRequestHeaders requestHeaders,
            HttpContentHeaders contentHeaders)
        {
            return CanonicalizeHttpHeaders(method, contentHeaders.ContentLength, requestHeaders, contentHeaders);
        }

        /// <summary>
        /// Canonicalizes the HTTP headers.
        /// </summary>
        /// <param name="method">The HTTP method for the request.</param>
        /// <param name="contentLength">The length of the content.</param>
        /// <param name="requestHeaders">The request headers.</param>
        /// <param name="contentHeaders">The content headers.</param>
        /// <returns>A string representation of the HTTP headers.</returns>
        private static string CanonicalizeHttpHeaders(
            HttpMethod method,
            long? contentLength,
            HttpRequestHeaders requestHeaders,
            HttpContentHeaders contentHeaders)
        {
            var headerPortion = new CanonicalizedStringBuilder();
            headerPortion.Append(method.Method.ToUpperInvariant());
            headerPortion.Append(contentHeaders.ContentEncoding);
            headerPortion.Append(contentHeaders.ContentLanguage);
            headerPortion.Append(contentLength == null ? string.Empty : ((long)contentLength).ToString(CultureInfo.InvariantCulture));
            headerPortion.Append(Convert.ToBase64String(contentHeaders.ContentMD5));
            headerPortion.Append(contentHeaders.ContentType);
            headerPortion.Append(requestHeaders.Date.HasValue ? requestHeaders.Date.Value.ToString("R", CultureInfo.InvariantCulture) : null);
            headerPortion.Append(requestHeaders.IfModifiedSince);
            headerPortion.Append(requestHeaders.IfMatch);
            headerPortion.Append(requestHeaders.IfNoneMatch);
            headerPortion.Append(requestHeaders.IfUnmodifiedSince);
            headerPortion.Append(requestHeaders.Range);
            return headerPortion.ToString();
        }

        /// <summary>
        /// Canonicalizes the custom headers.
        /// </summary>
        /// <param name="headers">A NameValueCollection of request headers.</param>
        /// <returns>A string representation of the custom HTTP headers.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Globalization", "CA1308:NormalizeStringsToUppercase", Justification = "Following the Azure REST API Specification.")]
        private static string CanonicalizeCustomHeaders(NameValueCollection headers)
        {
            // 1. Retrieve all headers for the resource that begin with x-ms-, including the x-ms-date header.
            // 3. Sort the headers lexicographically by header name, in ascending order. Note that each header may appear only once in the string.
            var microsoftHeaders = from h in headers.AllKeys.Distinct() where h.StartsWith("x-ms", StringComparison.OrdinalIgnoreCase) orderby h select h;

            var canoncializedHeaders = new StringBuilder();
            foreach (var header in microsoftHeaders)
            {
                // 2. Convert each HTTP header name to lowercase.
                canoncializedHeaders.Append(header.ToLowerInvariant());
                canoncializedHeaders.Append(':');

                // 4. Unfold the string by replacing any breaking white space with a single space.
                // 5. Trim any white space around the colon in the header.
                canoncializedHeaders.Append(headers[header].TrimStart().Replace('\t', ' ').Replace("\r\n", string.Empty));

                // 6. Finally, append a new line character to each canonicalized header in the resulting list.
                canoncializedHeaders.Append('\n');
            }

            return canoncializedHeaders.ToString();
        }

        /// <summary>
        /// Canonicalizes the resource details.
        /// </summary>
        /// <param name="path">The resource path.</param>
        /// <param name="queryString">The query string.</param>
        /// <param name="accountName">Name of the account accessing the resource.</param>
        /// <returns>A string representation of the resource details.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Globalization", "CA1308:NormalizeStringsToUppercase", Justification = "Following the Azure REST API Specification.")]
        private static string CanonicalizeResource(string path, NameValueCollection queryString, string accountName)
        {
            var canonicalizedResource = new CanonicalizedStringBuilder('/' + accountName + path);

            var queryStringParameters = from q in queryString.AllKeys.Distinct() orderby q select q;
            foreach (var key in queryStringParameters)
            {
                var parameterBuilder = new StringBuilder(key.ToLowerInvariant()).Append(':');
                foreach (var value in queryString[key])
                {
                    parameterBuilder.Append(value);
                    parameterBuilder.Append(',');
                }
                canonicalizedResource.Append(parameterBuilder.ToString().TrimEnd(','));
            }

            return canonicalizedResource.ToString();
        }

        /// <summary>
        /// Converts the specified headers to name value collection, where the value is the first header value encountered.
        /// </summary>
        /// <param name="headers">The headers to convert.</param>
        /// <returns>A NameValueCollection of headers and their first or default value.</returns>
        private static NameValueCollection ConvertToNameValueCollection(IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
        {
            var collection = new NameValueCollection();
            
            foreach (var header in headers)
            {
                string value = header.Value.FirstOrDefault();
                collection.Add(header.Key, value ?? string.Empty);
            }

            return collection;
        }
    }
}
