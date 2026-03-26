using HarmonyLib;
using Mirror;

namespace AntiDDoS.Patches.Optimizations
{
    [HarmonyPatch(typeof(NetworkServer), nameof(NetworkServer.BroadcastToConnection))]
    internal class NullEntryCleanup
    {
        // Fix "Found 'null' entry in observing list..." log spam
        private static void Postfix(NetworkConnectionToClient connection)
            => connection.observing.RemoveWhere(identity => identity == null);
    }
}