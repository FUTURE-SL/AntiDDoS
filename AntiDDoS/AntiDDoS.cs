using HarmonyLib;
using LabApi.Features;
using LabApi.Loader.Features.Plugins;
using System;

namespace AntiDDoS
{
    internal class AntiDDoS : Plugin
    {
        private Harmony? _harmony;

        public override string Name { get; } = nameof(AntiDDoS);
        public override string Description { get; } = "Anti-DDoS plugin related to connection attack protection + optimizations + exploit fixes.";
        public override string Author { get; } = "ФУТУР";
        public override Version Version { get; } = new Version(1, 0);
        public override Version RequiredApiVersion { get; } = new Version(LabApiProperties.CompiledVersion);

        public override void Enable()
        {
            _harmony = new Harmony($"{Author}.{Name}-{DateTime.Now}");
            _harmony.PatchAll();
        }

        public override void Disable()
        {
            _harmony?.UnpatchAll(_harmony.Id);
            _harmony = null;
        }
    }
}