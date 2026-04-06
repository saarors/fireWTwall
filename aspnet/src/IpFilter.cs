using System;
using System.Net;
using System.Net.Sockets;

namespace FireWTWall
{
    /// <summary>
    /// IP blacklist / whitelist filter with CIDR support (IPv4 and IPv6).
    /// </summary>
    public sealed class IpFilter
    {
        private readonly string[] _whitelist;
        private readonly string[] _blacklist;

        public IpFilter(string[] whitelist, string[] blacklist)
        {
            _whitelist = whitelist ?? Array.Empty<string>();
            _blacklist = blacklist ?? Array.Empty<string>();
        }

        /// <summary>Returns "whitelist", "blacklist", or null.</summary>
        public string Check(string ip)
        {
            if (_whitelist.Length > 0 && IpInList(ip, _whitelist)) return "whitelist";
            if (_blacklist.Length > 0 && IpInList(ip, _blacklist)) return "blacklist";
            return null;
        }

        // ------------------------------------------------------------------ //
        // Static helpers (used by WafRequest as well)
        // ------------------------------------------------------------------ //

        public static bool IpInList(string ip, string[] list)
        {
            foreach (var entry in list)
            {
                if (IpMatchesEntry(ip, entry)) return true;
            }
            return false;
        }

        public static bool IpMatchesEntry(string ip, string entry)
        {
            if (!entry.Contains("/")) return ip == entry;
            return IpInCidr(ip, entry);
        }

        public static bool IpInCidr(string ip, string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2) return false;
            if (!int.TryParse(parts[1], out int prefix)) return false;

            string range = parts[0];

            IPAddress ipAddr, rangeAddr;
            if (!IPAddress.TryParse(ip, out ipAddr) || !IPAddress.TryParse(range, out rangeAddr))
                return false;

            if (ipAddr.AddressFamily != rangeAddr.AddressFamily)
                return false;

            if (ipAddr.AddressFamily == AddressFamily.InterNetwork)
                return Ipv4InCidr(ipAddr, rangeAddr, prefix);

            return Ipv6InCidr(ipAddr, rangeAddr, prefix);
        }

        private static bool Ipv4InCidr(IPAddress ip, IPAddress range, int prefix)
        {
            uint ipInt    = IpToUint(ip.GetAddressBytes());
            uint rangeInt = IpToUint(range.GetAddressBytes());
            uint mask     = prefix == 0 ? 0u : ~(0xFFFFFFFFu >> prefix);
            return (ipInt & mask) == (rangeInt & mask);
        }

        private static uint IpToUint(byte[] bytes)
        {
            return (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
        }

        private static bool Ipv6InCidr(IPAddress ip, IPAddress range, int prefix)
        {
            byte[] ipBytes    = ip.GetAddressBytes();
            byte[] rangeBytes = range.GetAddressBytes();

            int fullBytes = prefix / 8;
            int remainder = prefix % 8;

            for (int i = 0; i < fullBytes; i++)
            {
                if (ipBytes[i] != rangeBytes[i]) return false;
            }

            if (remainder > 0 && fullBytes < ipBytes.Length)
            {
                byte mask = (byte)(0xFF << (8 - remainder));
                if ((ipBytes[fullBytes] & mask) != (rangeBytes[fullBytes] & mask))
                    return false;
            }

            return true;
        }
    }
}
