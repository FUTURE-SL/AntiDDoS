using HarmonyLib;
using LiteNetLib;
using System;
using System.Collections.Generic;

namespace AntiDDoS.Patches.Optimizations
{
    [HarmonyPatch(typeof(NetDebug), nameof(NetDebug.WriteLogic))]
    internal class NetDebugShutUp
    {
        private const int MaxLogsPerSecond = 10;

        private class LogRateState
        {
            public int Count;
            public DateTime NextResetTime;
        }

        private static readonly Dictionary<NetLogLevel, LogRateState> _states = new Dictionary<NetLogLevel, LogRateState>();

        private static readonly object _lock = new object();

        private static bool Prefix(NetLogLevel logLevel)
        {
            lock (_lock)
            {
                DateTime now = DateTime.UtcNow;

                if (!_states.TryGetValue(logLevel, out LogRateState state))
                {
                    state = new LogRateState
                    {
                        Count = 0,
                        NextResetTime = now.AddSeconds(1)
                    };
                    _states[logLevel] = state;
                }

                if (now >= state.NextResetTime)
                {
                    state.Count = 0;
                    state.NextResetTime = now.AddSeconds(1);
                }

                if (state.Count < MaxLogsPerSecond)
                {
                    state.Count++;
                    return true;
                }

                return false;
            }
        }
    }
}