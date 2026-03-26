using System;
using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace AntiDDoS.Tokens
{
    internal sealed class ChallengeResponse : HmacTokenProvider<byte[]>
    {
        public static readonly ChallengeResponse Instance = new();

        private const ushort Ttl = 3;

        internal const int TokenSize = 10;

        private const int TimestampSize = sizeof(ushort);
        private const int SignatureSize = 8;
        private const int SignatureOffset = TimestampSize;

        private ChallengeResponse() { }

        public void GenerateTo(IPEndPoint endPoint, Span<byte> destination)
        {
            ushort timestamp = CurrentTimeShort();
            BinaryPrimitives.WriteUInt16LittleEndian(destination, timestamp);

            Span<byte> hash = stackalloc byte[32];
            BuildAndHash(endPoint.Address, timestamp, hash);
            hash[..SignatureSize].CopyTo(destination[SignatureOffset..]);
        }

        public override byte[] Generate(IPEndPoint endPoint)
        {
            byte[] token = new byte[TokenSize];
            GenerateTo(endPoint, token);
            return token;
        }

        public override bool Validate(IPEndPoint point, byte[] token) =>
            Validate(point, token.AsSpan());

        public bool Validate(IPEndPoint point, ReadOnlySpan<byte> token)
        {
            if (token.Length != TokenSize)
                return false;

            ushort tokenTime = BinaryPrimitives.ReadUInt16LittleEndian(token);

            ushort age = (ushort)(CurrentTimeShort() - tokenTime);
            if (age > Ttl)
                return false;

            Span<byte> expectedHash = stackalloc byte[32];
            BuildAndHash(point.Address, tokenTime, expectedHash);

            return CryptographicOperations.FixedTimeEquals(
                token[SignatureOffset..TokenSize],
                expectedHash[..SignatureSize]);
        }

        private static ushort CurrentTimeShort() =>
            (ushort)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() & 0xFFFF);

        private void BuildAndHash(IPAddress ip, ushort timeShort, Span<byte> destination)
        {
            Span<byte> ipBytes = stackalloc byte[16];
            ip.TryWriteBytes(ipBytes, out int ipLength);

            Span<byte> buffer = stackalloc byte[16 + TimestampSize];
            ipBytes[..ipLength].CopyTo(buffer);
            BinaryPrimitives.WriteUInt16LittleEndian(buffer[ipLength..], timeShort);

            ComputeHash(buffer[..(ipLength + TimestampSize)], destination);
        }
    }
}