using System;
using System.Net;
using System.Security.Cryptography;

namespace AntiDDoS.Tokens
{
    internal abstract class HmacTokenProvider<TToken>
    {
        private readonly HMACSHA256 _hmac;

        protected HmacTokenProvider()
        {
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            _hmac = new HMACSHA256(key);
        }

        public abstract TToken Generate(IPEndPoint point);
        public abstract bool Validate(IPEndPoint point, TToken token);

        protected void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination) =>
            _hmac.TryComputeHash(data, destination, out _);
    }
}