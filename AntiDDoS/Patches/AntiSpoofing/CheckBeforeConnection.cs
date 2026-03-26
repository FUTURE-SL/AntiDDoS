using AntiDDoS.Tokens;
using HarmonyLib;
using LiteNetLib;
using Steam;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace AntiDDoS.Patches.AntiSpoofing
{
    [HarmonyPatch(typeof(LiteNetManager), nameof(LiteNetManager.OnMessageReceived))]
    internal static class CheckBeforeConnection
    {
        private const int ConnectionTimeOffset = 5;
        private const int ConnectionTimeLength = 8;
        private const int ConnectDataLengthOffset = 38;
        private const int MinConnectRequestSize = ConnectDataLengthOffset + 1;

        private const int SeqPrefixLength = 4;
        private const int SeqResponseTokenLength = sizeof(uint);
        private const int SeqChallengeSize = SeqPrefixLength + 1 + SeqResponseTokenLength;

        private const byte SeqInfo = 0x54;
        private const byte SeqChallenge = 0x41;

        private const byte ChallengePayloadSize = 13;
        private const int ChallengeNonce = 1;

        private const byte AcceptedPayloadSize = 17;
        private const byte AcceptedCode = 1;

        private const int DisconnectHeaderSize = 1 + ConnectionTimeLength + 1;
        private const int ChallengeReplySize =
            DisconnectHeaderSize + 1 + sizeof(int) + sizeof(ushort) + ChallengeResponse.TokenSize;
        private const int AcceptedSize = DisconnectHeaderSize + 1;

        private static readonly HashSet<IPAddress> _whiteList = new();

        private static bool Prefix(LiteNetManager __instance, NetPacket packet, IPEndPoint remoteEndPoint)
        {
            ReadOnlySpan<byte> data = packet.RawData.AsSpan(0, packet.Size);

            if (data.IsEmpty)
                return true;

            if (IsSourceEngineQuery(data))
            {
                PreAuthLogger.Processed++;

                ProcessSEQ(__instance, data, remoteEndPoint);
                __instance.PoolRecycle(packet);
                return false;
            }

            if (_whiteList.Contains(remoteEndPoint.Address))
                return true;

            if (packet.Property != PacketProperty.ConnectRequest)
            {
                __instance.PoolRecycle(packet);
                return false;
            }

            PreAuthLogger.Processed++;

            if (!TryParseChallenge(data, out int nonce, out ReadOnlySpan<byte> challenge))
            {
                __instance.PoolRecycle(packet);
                return false;
            }

            ReadOnlySpan<byte> connTime = data.Slice(ConnectionTimeOffset, ConnectionTimeLength);

            if (nonce == 0 || challenge.IsEmpty)
            {
                SendChallengeRequest(__instance, remoteEndPoint, connTime);
            }
            else
            {
                if (!ChallengeResponse.Instance.Validate(remoteEndPoint, challenge))
                {
                    __instance.PoolRecycle(packet);
                    return false;
                }

                _whiteList.Add(remoteEndPoint.Address);
                SendAccepted(__instance, remoteEndPoint, connTime);
            }

            __instance.PoolRecycle(packet);
            return false;
        }

        private static bool IsSourceEngineQuery(ReadOnlySpan<byte> data) =>
            data.Length >= SeqChallengeSize &&
            BinaryPrimitives.ReadUInt32LittleEndian(data) == 0xFFFFFFFF;

        private static void ProcessSEQ(LiteNetManager instance, ReadOnlySpan<byte> data, IPEndPoint ep)
        {
            if (data[SeqPrefixLength] != SeqInfo)
                return;

            ReadOnlySpan<byte> payload = data[(SeqPrefixLength + 1)..];
            int nullIdx = payload.IndexOf((byte)0);
            if (nullIdx < 0)
                return;

            ReadOnlySpan<byte> afterNull = payload[(nullIdx + 1)..];

            if (afterNull.Length >= SeqResponseTokenLength)
            {
                uint response = BinaryPrimitives.ReadUInt32LittleEndian(afterNull);

                if (SourceEngineQuery.Instance.Validate(ep, response))
                    instance._udpSocketv4.SendTo(SteamServerInfo.Serialize(), SocketFlags.None, ep);
                else
                    NetDebug.WriteError($"[SEQ] Bad HMAC from {ep}");

                return;
            }

            byte[] buf = ArrayPool<byte>.Shared.Rent(SeqChallengeSize);
            try
            {
                Span<byte> span = buf.AsSpan(0, SeqChallengeSize);
                BinaryPrimitives.WriteUInt32LittleEndian(span, 0xFFFFFFFF);
                span[4] = SeqChallenge;
                BinaryPrimitives.WriteUInt32LittleEndian(span[5..], SourceEngineQuery.Instance.Generate(ep));

                instance._udpSocketv4.SendTo(buf, 0, SeqChallengeSize, SocketFlags.None, ep);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        private static bool TryParseChallenge(
            ReadOnlySpan<byte> data,
            out int nonce,
            out ReadOnlySpan<byte> challenge)
        {
            nonce = 0;
            challenge = default;

            if (data.Length < MinConnectRequestSize)
                return false;

            byte customLen = data[ConnectDataLengthOffset];
            int cursor = ConnectDataLengthOffset + 1 + customLen;

            if (data.Length < cursor + sizeof(int))
                return true;

            nonce = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(cursor, sizeof(int)));
            cursor += sizeof(int);

            if (data.Length < cursor + sizeof(ushort))
                return true;

            int challengeLen = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor, sizeof(ushort)));
            cursor += sizeof(ushort);

            if (data.Length < cursor + challengeLen)
                return false;

            challenge = data.Slice(cursor, challengeLen);
            return true;
        }

        private static void SendChallengeRequest(LiteNetManager instance, IPEndPoint ep, ReadOnlySpan<byte> connTime)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(ChallengeReplySize);
            try
            {
                Span<byte> span = buf.AsSpan(0, ChallengeReplySize);
                int cur = 0;

                span[cur++] = (byte)PacketProperty.Disconnect;
                connTime.CopyTo(span.Slice(cur, ConnectionTimeLength));
                cur += ConnectionTimeLength;

                span[cur++] = ChallengePayloadSize;
                span[cur++] = (byte)ChallengeType.Reply;
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(cur, sizeof(int)), ChallengeNonce);
                cur += sizeof(int);

                BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(cur, sizeof(ushort)), ChallengeResponse.TokenSize);
                cur += sizeof(ushort);

                ChallengeResponse.Instance.GenerateTo(ep, span.Slice(cur, ChallengeResponse.TokenSize));

                instance._udpSocketv4.SendTo(buf, 0, ChallengeReplySize, SocketFlags.None, ep);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        private static void SendAccepted(LiteNetManager instance, IPEndPoint ep, ReadOnlySpan<byte> connTime)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(AcceptedSize);
            try
            {
                Span<byte> span = buf.AsSpan(0, AcceptedSize);
                int cur = 0;

                span[cur++] = (byte)PacketProperty.Disconnect;
                connTime.CopyTo(span.Slice(cur, ConnectionTimeLength));
                cur += ConnectionTimeLength;

                span[cur++] = AcceptedPayloadSize;
                span[cur++] = AcceptedCode;

                instance._udpSocketv4.SendTo(buf, 0, AcceptedSize, SocketFlags.None, ep);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
    }
}