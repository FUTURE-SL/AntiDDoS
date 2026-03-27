using AntiDDoS.Patches.AntiSpoofing;

namespace AntiDDoS.Tokens
{
    internal sealed class SourceEngineQuery
    {
        public static readonly SourceEngineQuery Instance = new();

        private const long TimeWindowSeconds = 3;

        private SourceEngineQuery() { }

        public uint Generate(uint ipv4) =>
            SlotHash(ipv4, CurrentSlot());

        public bool Validate(uint ipv4, uint token)
        {
            long slot = CurrentSlot();

            return SlotHash(ipv4, slot) == token
                || SlotHash(ipv4, slot - 1) == token;
        }

        private static uint SlotHash(uint ipv4, long slot) =>
            (uint)SipHash24Provider.Hash(ipv4, slot);

        private static long CurrentSlot() =>
            FastClock.UnixSeconds() / TimeWindowSeconds;
    }
}