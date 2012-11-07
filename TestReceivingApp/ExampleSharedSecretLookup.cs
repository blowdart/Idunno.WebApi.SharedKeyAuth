using System;
using System.Collections.Generic;

namespace TestReceivingApp
{
    public static class ExampleSharedSecretLookup
    {
        private static readonly Dictionary<string, byte[]> Secrets = new Dictionary<string, byte[]> 
        {
            { "barryd", Convert.FromBase64String("KUreulZKB1y//AIuXQInef7X66LRWbeCIJyQyMH33sbkmuFwk7Z+U7/iTj9MNFY/ynaHg5NenUbJKfxWLLNVsw==") }
        };

        public static byte[] Lookup(string accountName)
        {
            return !Secrets.ContainsKey(accountName) ? null : Secrets[accountName];
        }
    }
}