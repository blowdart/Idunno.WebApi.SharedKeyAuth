//-----------------------------------------------------------------------
// <copyright file="CanonicalizedStringBuilder.cs" company="Microsoft">
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

using System.Text;

namespace Idunno.WebApi.SharedKeyAuthentication
{
    /// <summary>
    /// Builds a canonicalized string by separating values with a newline character.
    /// </summary>
    internal class CanonicalizedStringBuilder
    {
        /// <summary>
        /// Internal string builder used to construct the canonicalized string.
        /// </summary>
        private readonly StringBuilder stringBuilder = new StringBuilder();

        /// <summary>
        /// Initializes a new instance of the <see cref="CanonicalizedStringBuilder" /> class.
        /// </summary>
        public CanonicalizedStringBuilder()
        {            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CanonicalizedStringBuilder" /> class.
        /// </summary>
        /// <param name="initialString">The initial string to initialize the string builder with..</param>
        public CanonicalizedStringBuilder(string initialString)
        {
            this.Append(initialString);
        }

        /// <summary>
        /// Appends the string representation of a specified object to this instance.
        /// </summary>
        /// <param name="value">The object to append.</param>
        /// <returns>A reference to this instance after the append operation has completed.</returns>
        public CanonicalizedStringBuilder Append(object value)
        {
            this.stringBuilder.Append(value);
            this.stringBuilder.Append('\n');

            return this;
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            return this.stringBuilder.ToString();
        }
    }
}
