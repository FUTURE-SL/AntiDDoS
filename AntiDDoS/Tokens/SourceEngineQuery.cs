using System;
using System.Buffers.Binary;
using System.Net;

namespace AntiDDoS.Tokens
{
    internal sealed class SourceEngineQuery : HmacTokenProvider<uint>
    {
        public static readonly SourceEngineQuery Instance = new();

        private const long TimeWindowSeconds = 3;

        private SourceEngineQuery() { }

        public override uint Generate(IPEndPoint point) =>
            SlotHash(point.Address, CurrentSlot());

        public override bool Validate(IPEndPoint point, uint token)
        {
            long slot = CurrentSlot();

            return SlotHash(point.Address, slot) == token
                || SlotHash(point.Address, slot - 1) == token;
        }

        private static long CurrentSlot() =>
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() / TimeWindowSeconds;

        private uint SlotHash(IPAddress ip, long timeSlot)
        {
            Span<byte> ipBytes = stackalloc byte[16];
            ip.TryWriteBytes(ipBytes, out int ipLength);

            Span<byte> buffer = stackalloc byte[16 + sizeof(long)];
            ipBytes[..ipLength].CopyTo(buffer);
            BinaryPrimitives.WriteInt64LittleEndian(buffer[ipLength..], timeSlot);

            Span<byte> hash = stackalloc byte[32];
            ComputeHash(buffer[..(ipLength + sizeof(long))], hash);

            return BinaryPrimitives.ReadUInt32LittleEndian(hash);
        }
    }
}