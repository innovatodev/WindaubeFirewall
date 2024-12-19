using System.Buffers.Binary;
using System.IO;
using System.Net;

namespace WindaubeFirewall.Driver;

public class DriverInfoReader
{
    private const byte LogLine = 0;
    private const byte ConnectionV4 = 1;
    private const byte ConnectionV6 = 2;
    private const byte ConnectionEndV4 = 3;
    private const byte ConnectionEndV6 = 4;
    private const byte BandwidthStatsV4 = 5;
    private const byte BandwidthStatsV6 = 6;

    public static DriverInfo? ReceiveInfo()
    {
        var reader = DriverWorker.KextBinaryReader;
        if (reader == null || !reader.BaseStream.CanRead)
        {
            return null;
        }

        try
        {
            // Read header in one go
            var header = reader.ReadBytes(5);
            if (header.Length != 5)
            {
                return null; // Not enough data available
            }

            byte infoType = header[0];
            uint commandSize = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(header, 1, 4));

            // Only continue if we have a valid info type
            if (!Enum.IsDefined(typeof(InfoType), infoType))
            {
                Logger.Log($"Invalid info type received: {infoType}");
                return null;
            }

            return infoType switch
            {
                LogLine => new DriverInfo { LogLine = DriverInfoLogLine.Parse(reader, (int)commandSize) },
                ConnectionV4 => new DriverInfo { ConnectionV4 = DriverInfoConnection.Parse(reader, false) },
                ConnectionV6 => new DriverInfo { ConnectionV6 = DriverInfoConnection.Parse(reader, true) },
                ConnectionEndV4 => new DriverInfo { ConnectionEndV4 = DriverInfoConnectionEnd.Parse(reader, false) },
                ConnectionEndV6 => new DriverInfo { ConnectionEndV6 = DriverInfoConnectionEnd.Parse(reader, true) },
                BandwidthStatsV4 => new DriverInfo { BandwidthStats = DriverInfoBandwidthStats.Parse(reader, false) },
                BandwidthStatsV6 => new DriverInfo { BandwidthStats = DriverInfoBandwidthStats.Parse(reader, true) },
                _ => null,
            };
        }
        catch (EndOfStreamException)
        {
            return null; // No more data to read
        }
        catch (ObjectDisposedException)
        {
            return null;
        }
        catch (Exception ex)
        {
            Logger.Log($"Error reading info: {ex.Message}");
            return null;
        }
    }

    private enum InfoType : byte
    {
        LogLine = 0,
        ConnectionV4 = 1,
        ConnectionV6 = 2,
        ConnectionEndV4 = 3,
        ConnectionEndV6 = 4,
        BandwidthStatsV4 = 5,
        BandwidthStatsV6 = 6
    }

    public static List<DriverInfo> ReceiveInfoAll()
    {
        var infos = new List<DriverInfo>();
        var reader = DriverWorker.KextBinaryReader;
        if (reader == null || !reader.BaseStream.CanRead)
        {
            return infos;
        }

        while (true)
        {
            try
            {
                var info = ReceiveInfo();
                if (info != null)
                {
                    infos.Add(info);
                }
                else
                {
                    break;
                }
            }
            catch (IOException)
            {
                // No more data available
                break;
            }
            catch (Exception ex)
            {
                Logger.Log($"Error reading info: {ex.Message}");
                break;
            }
        }

        return infos;
    }

    public record DriverInfo
    {
        public DriverInfoLogLine? LogLine;
        public DriverInfoConnection? ConnectionV4;
        public DriverInfoConnection? ConnectionV6;
        public DriverInfoConnectionEnd? ConnectionEndV4;
        public DriverInfoConnectionEnd? ConnectionEndV6;
        public DriverInfoBandwidthStats? BandwidthStats;
    }

    public record DriverInfoLogLine
    {
        required public int Severity { get; init; }
        required public string Line { get; init; }

        public static DriverInfoLogLine Parse(BinaryReader reader, int commandSize)
        {
            return new DriverInfoLogLine
            {
                Severity = reader.ReadByte(),
                Line = System.Text.Encoding.UTF8.GetString(reader.ReadBytes(commandSize - 1))
            };
        }

        public void Print() => Logger.Log($"LogLine: {Severity} : {Line}");
    }

    public record ConnectionBase
    {
        required public ulong ProcessID { get; init; }
        required public byte Direction { get; init; }
        required public byte Protocol { get; init; }
        required public IPAddress LocalIP { get; init; }
        required public IPAddress RemoteIP { get; init; }
        required public ushort LocalPort { get; init; }
        required public ushort RemotePort { get; init; }

        protected static (IPAddress local, IPAddress remote) ReadAddresses(BinaryReader reader, bool isV6)
        {
            var size = isV6 ? 16 : 4;
            return (
                new IPAddress(reader.ReadBytes(size)),
                new IPAddress(reader.ReadBytes(size))
            );
        }

        public virtual void Print() =>
            Logger.Log($"{GetType().Name}: {LocalIP}:{LocalPort} - {RemoteIP}:{RemotePort} {StringConverters.ProtocolToString(Protocol)} {StringConverters.DirectionToString(Direction)} {ProcessID}");
    }

    public record DriverInfoConnection : ConnectionBase
    {
        required public ulong ID { get; init; }
        required public byte PayloadLayer { get; init; }
        required public uint PayloadSize { get; init; }
        public byte[]? Payload { get; init; }

        public static DriverInfoConnection Parse(BinaryReader reader, bool isV6)
        {
            var id = reader.ReadUInt64();
            var pid = reader.ReadUInt64();
            var direction = reader.ReadByte();
            var protocol = reader.ReadByte();
            var (local, remote) = ReadAddresses(reader, isV6);
            var localPort = reader.ReadUInt16();
            var remotePort = reader.ReadUInt16();
            var layer = reader.ReadByte();
            var size = reader.ReadUInt32();

            return new DriverInfoConnection
            {
                ID = id,
                ProcessID = pid,
                Direction = direction,
                Protocol = protocol,
                LocalIP = local,
                RemoteIP = remote,
                LocalPort = localPort,
                RemotePort = remotePort,
                PayloadLayer = layer,
                PayloadSize = size,
                Payload = size > 0 ? reader.ReadBytes((int)size) : null
            };
        }

        public override void Print() =>
            Logger.Log($"{GetType().Name}: {LocalIP}:{LocalPort} - {RemoteIP}:{RemotePort} {StringConverters.ProtocolToString(Protocol)} {StringConverters.DirectionToString(Direction)} {PayloadLayer} {PayloadSize} {ProcessID} {ID}");
    }

    public record DriverInfoConnectionEnd : ConnectionBase
    {
        public static DriverInfoConnectionEnd Parse(BinaryReader reader, bool isV6)
        {
            var pid = reader.ReadUInt64();
            var direction = reader.ReadByte();
            var protocol = reader.ReadByte();
            var (local, remote) = ReadAddresses(reader, isV6);
            var localPort = reader.ReadUInt16();
            var remotePort = reader.ReadUInt16();

            return new DriverInfoConnectionEnd
            {
                ProcessID = pid,
                Direction = direction,
                Protocol = protocol,
                LocalIP = local,
                RemoteIP = remote,
                LocalPort = localPort,
                RemotePort = remotePort
            };
        }
        public override void Print() =>
           Logger.Log($"{GetType().Name}: {LocalIP}:{LocalPort} - {RemoteIP}:{RemotePort} {StringConverters.ProtocolToString(Protocol)} {StringConverters.DirectionToString(Direction)} {ProcessID}");
    }

    public record BandwidthValueBase
    {
        required public IPAddress LocalIP { get; init; }
        required public ushort LocalPort { get; init; }
        required public IPAddress RemoteIP { get; init; }
        required public ushort RemotePort { get; init; }
        required public ulong TransmittedBytes { get; init; }
        required public ulong ReceivedBytes { get; init; }

        public virtual void Print() =>
            Logger.Log($"{GetType().Name}: {LocalIP}:{LocalPort} - {RemoteIP}:{RemotePort} {TransmittedBytes} {ReceivedBytes}");

        public static BandwidthValueBase Parse(BinaryReader reader, bool isV6)
        {
            var size = isV6 ? 16 : 4;
            return new BandwidthValueBase
            {
                LocalIP = new IPAddress(reader.ReadBytes(size)),
                LocalPort = reader.ReadUInt16(),
                RemoteIP = new IPAddress(reader.ReadBytes(size)),
                RemotePort = reader.ReadUInt16(),
                TransmittedBytes = reader.ReadUInt64(),
                ReceivedBytes = reader.ReadUInt64()
            };
        }
    }

    public record DriverInfoBandwidthStats
    {
        private const int MaxArraySize = 1000000;

        required public byte Protocol { get; init; }
        required public List<BandwidthValueBase> Values { get; init; }

        public static DriverInfoBandwidthStats Parse(BinaryReader reader, bool isV6)
        {
            byte protocol = reader.ReadByte();
            uint size = reader.ReadUInt32();

            if (size > MaxArraySize || size == 0)
            {
                throw new IOException($"Invalid array size: {size}");
            }

            var values = new List<BandwidthValueBase>((int)size);
            for (uint i = 0; i < size; i++)
            {
                values.Add(BandwidthValueBase.Parse(reader, isV6));
            }

            return new DriverInfoBandwidthStats
            {
                Protocol = protocol,
                Values = values
            };
        }

        public void Print() => Values.ForEach(v => v.Print());
    }

}
