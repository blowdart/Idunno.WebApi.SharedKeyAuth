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

namespace Idunno.WebApi.SharedKeyAuthentication
{
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when authentication fails.
    /// </summary>
    [Serializable]
    public class ForbiddenException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ForbiddenException" /> class.
        /// </summary>
        public ForbiddenException()
        {            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ForbiddenException" /> class.
        /// </summary>
        /// <param name="message">A message that describes why this <see cref="ForbiddenException" /> exception was thrown.</param>
        public ForbiddenException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ForbiddenException" /> class.
        /// </summary>
        /// <param name="message">A message that describes why this <see cref="ForbiddenException" /> exception was thrown.</param>
        /// <param name="inner">The exception that caused this <see cref="ForbiddenException" /> exception to be thrown.</param>
        public ForbiddenException(string message, Exception inner) : base(message, inner)
        {    
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ForbiddenException" /> class.
        /// </summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
        protected ForbiddenException(SerializationInfo info, StreamingContext context) : base(info, context)
        {            
        }
    }
}
