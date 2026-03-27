using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace AntiDDoS.Tokens
{
    internal static class SipHash24Provider
    {
        private static readonly ulong K0;
        private static readonly ulong K1;

        static SipHash24Provider()
        {
            Span<byte> key = stackalloc byte[16];
            RandomNumberGenerator.Fill(key);
            K0 = BinaryPrimitives.ReadUInt64LittleEndian(key);
            K1 = BinaryPrimitives.ReadUInt64LittleEndian(key[8..]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Hash(uint ipv4, ushort value)
        {
            ulong m0 = ipv4 | ((ulong)value << 32) | (6UL << 56);
            return Core_OneBlock(m0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Hash(uint ipv4, long slot)
        {
            ulong m0 = ipv4 | ((ulong)(uint)slot << 32);
            ulong m1 = ((ulong)slot >> 32) | (12UL << 56);
            return Core_TwoBlocks(m0, m1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Core_OneBlock(ulong m0)
        {
            ulong v0 = K0 ^ 0x736f6d6570736575UL;
            ulong v1 = K1 ^ 0x646f72616e646f6dUL;
            ulong v2 = K0 ^ 0x6c7967656e657261UL;
            ulong v3 = K1 ^ 0x7465646279746573UL;

            v3 ^= m0;
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);
            v0 ^= m0;

            v2 ^= 0xFF;
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);

            return v0 ^ v1 ^ v2 ^ v3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Core_TwoBlocks(ulong m0, ulong m1)
        {
            ulong v0 = K0 ^ 0x736f6d6570736575UL;
            ulong v1 = K1 ^ 0x646f72616e646f6dUL;
            ulong v2 = K0 ^ 0x6c7967656e657261UL;
            ulong v3 = K1 ^ 0x7465646279746573UL;

            v3 ^= m0;
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);
            v0 ^= m0;

            v3 ^= m1;
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);
            v0 ^= m1;

            v2 ^= 0xFF;
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);

            return v0 ^ v1 ^ v2 ^ v3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
        {
            v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32);
            v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2;
            v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0;
            v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32);
        }
    }
}