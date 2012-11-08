﻿//-----------------------------------------------------------------------
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

namespace Idunno.WebApi.SharedKeyAuthentication
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the MD5 header validation fails.
    /// </summary>
    [Serializable]
    public class PreconditionFailedException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PreconditionFailedException" /> class.
        /// </summary>
        public PreconditionFailedException()
        {            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PreconditionFailedException" /> class.
        /// </summary>
        /// <param name="message">A message that describes why this <see cref="PreconditionFailedException" /> exception was thrown.</param>
        public PreconditionFailedException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PreconditionFailedException" /> class.
        /// </summary>
        /// <param name="message">A message that describes why this <see cref="PreconditionFailedException" /> exception was thrown.</param>
        /// <param name="inner">The exception that caused this <see cref="PreconditionFailedException" /> exception to be thrown.</param>
        public PreconditionFailedException(string message, Exception inner) : base(message, inner)
        {            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PreconditionFailedException" /> class.
        /// </summary>
        /// <param name="info">The object that holds the information to deserialize.</param>
        /// <param name="context">The object that holds the information to deserialize.</param>
        protected PreconditionFailedException(SerializationInfo info, StreamingContext context) : base(info, context)
        {            
        }
    }
}