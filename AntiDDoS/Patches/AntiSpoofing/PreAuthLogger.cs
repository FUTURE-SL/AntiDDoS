using HarmonyLib;
using System;
using UnityEngine;

using Logger = LabApi.Features.Console.Logger;

namespace AntiDDoS.Patches.AntiSpoofing
{
    [HarmonyPatch(typeof(CustomNetworkManager), nameof(CustomNetworkManager.FixedUpdate))]
    internal class PreAuthLogger
    {
        public static uint Processed;

        private static float _time;

        private static void Prefix()
        {
            _time += Time.fixedUnscaledDeltaTime;
            if (_time < 10)
                return;

            _time = 0;

            if (Processed == 0)
                return;

            string message = string.Format("Anti-Spoofing processed {0} connection[s] within the last 10 seconds.", Processed);
            if (Processed > 10000)
                Logger.Raw(message, ConsoleColor.Red);
            else if (Processed > 100)
                Logger.Raw(message, ConsoleColor.Yellow);
            else
                Logger.Raw(message, ConsoleColor.Gray);

            Processed = 0;
        }
    }
}