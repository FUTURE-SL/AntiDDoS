using System;
using System.Buffers.Binary;

namespace AntiDDoS.Tokens
{
    internal sealed class ChallengeResponse
    {
        public static readonly ChallengeResponse Instance = new();

        private const ushort Ttl = 3;

        internal const int TokenSize = 10;

        private const int TimestampSize = sizeof(ushort);
        private const int SignatureOffset = TimestampSize;

        private ChallengeResponse() { }

        public void GenerateTo(uint ipv4, Span<byte> destination)
        {
            ushort timestamp = CurrentTimeShort();
            BinaryPrimitives.WriteUInt16LittleEndian(destination, timestamp);

            ulong hash = SipHash24Provider.Hash(ipv4, timestamp);
            BinaryPrimitives.WriteUInt64LittleEndian(destination[SignatureOffset..], hash);
        }

        public bool Validate(uint ipv4, ReadOnlySpan<byte> token)
        {
            if (token.Length != TokenSize)
                return false;

            ushort tokenTime = BinaryPrimitives.ReadUInt16LittleEndian(token);

            ushort age = (ushort)(CurrentTimeShort() - tokenTime);
            if (age > Ttl)
                return false;

            ulong expected = SipHash24Provider.Hash(ipv4, tokenTime);
            ulong actual = BinaryPrimitives.ReadUInt64LittleEndian(token[SignatureOffset..]);

            return expected == actual;
        }

        private static ushort CurrentTimeShort() =>
            (ushort)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() & 0xFFFF);
    }
}