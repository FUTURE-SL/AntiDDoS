using System;
using System.Diagnostics;

namespace AntiDDoS.Patches.AntiSpoofing
{
    internal static class FastClock
    {
        private static readonly long TickFrequency = Stopwatch.Frequency;

        private static long _cachedSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        private static long _cachedTick = Stopwatch.GetTimestamp();

        public static long UnixSeconds()
        {
            long now = Stopwatch.GetTimestamp();
            if (now - _cachedTick >= TickFrequency)
            {
                _cachedSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                _cachedTick = now;
            }

            return _cachedSeconds;
        }
    }
}