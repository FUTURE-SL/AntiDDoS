using HarmonyLib;
using LabApi.Features.Console;
using Mirror;
using System;
using System.Linq;

namespace AntiDDoS.Patches
{
    internal class SecureNetThreading
    {
        [HarmonyPatch(typeof(NetworkWriterPool), nameof(NetworkWriterPool.Get))]
        internal class NetworkWriterPoolGet
        {
            private static void Prefix() => IsThreadSafe("NetworkWriterPool.Get");
        }

        [HarmonyPatch(typeof(NetworkWriterPool), nameof(NetworkWriterPool.Return))]
        internal class NetworkWriterPoolReturn
        {
            private static void Prefix() => IsThreadSafe("NetworkWriterPool.Return");
        }

        [HarmonyPatch(typeof(NetworkConnection), nameof(NetworkConnection.Send), new[] { typeof(ArraySegment<byte>), typeof(int) })]
        internal class NetworkConnectionSend
        {
            private static bool Prefix() => IsThreadSafe("NetworkConnection.Send");
        }

        private static bool IsThreadSafe(string methodName)
        {
            if (UnityEngine.Object.CurrentThreadIsMainThread())
                return true;

            string cleanStack = string.Join("\n", Environment.StackTrace.
                Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(line => !line.Contains(nameof(SecureNetThreading)) && !line.Contains("System.Environment")));

            Logger.Error($"\n[CRITICAL THREAD VIOLATION] Detected access to {methodName} from background thread!\n" +
                         $"This causes local NetworkClient crash.\n" +
                         $"STACK TRACE:\n{cleanStack}\n");

            return false;
        }
    }
}