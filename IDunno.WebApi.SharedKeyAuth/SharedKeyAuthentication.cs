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

namespace Idunno.WebApi.SharedKeyAuthentication
{
    /// <summary>
    /// Provides helpers for parsing an authentication header.
    /// </summary>
    internal static class SharedKeyAuthentication
    {
        /// <summary>
        /// The name of the authentication type.
        /// </summary>
        public static string Scheme
        {
            get
            {
                return "SharedKey";
            }
        }

        /// <summary>
        /// Tries to parse an authentication header value into an account name and HMAC.
        /// </summary>
        /// <param name="authenticationHeaderValue">The authentication header value.</param>
        /// <param name="accountName">Name of the account.</param>
        /// <param name="hmac">The HMAC.</param>
        /// <returns>True if parsing was successful, otherwise false.</returns>
        public static bool TryParse(string authenticationHeaderValue, out string accountName, out string hmac)
        {
            if (authenticationHeaderValue.Contains(":"))
            {
                var colonPosition = authenticationHeaderValue.IndexOf(":", StringComparison.OrdinalIgnoreCase);
                if (colonPosition != 0 && colonPosition != authenticationHeaderValue.Length)
                {
                    accountName = authenticationHeaderValue.Substring(0, colonPosition);
                    hmac = authenticationHeaderValue.Substring(colonPosition + 1);
                    return true;
                }
            }

            accountName = null;
            hmac = null;
            return false;
        }

        /// <summary>
        /// Tries to parse an authentication header value into an account name and HMAC.
        /// </summary>
        /// <param name="authenticationHeaderValue">The authentication header value.</param>
        /// <param name="accountName">Name of the account.</param>
        /// <param name="hmac">The HMAC.</param>
        /// <returns>True if parsing was successful, otherwise false.</returns>
        public static bool TryParse(string authenticationHeaderValue, out string accountName, out byte[] hmac)
        {
            string hmacAsString;
            bool result = TryParse(authenticationHeaderValue, out accountName, out hmacAsString);

            hmac = result ? Convert.FromBase64String(hmacAsString) : null;

            return result;
        }
    }
}
