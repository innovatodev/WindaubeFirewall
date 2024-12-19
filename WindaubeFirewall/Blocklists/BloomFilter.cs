using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace WindaubeFirewall.Blocklists;

public class BloomFilter
{
    private readonly BitArray _bits;
    private readonly int _hashFunctions;
    private readonly int _bitSize;

    private const int CACHE_SIZE = 1000;
    private readonly HashSet<string> _recentFalsePositives = new(CACHE_SIZE);
    private readonly object _cacheLock = new();

    // Reduced default false positive rate for better accuracy
    public BloomFilter(int capacity, double falsePositiveRate = 0.0001) // Reduced to 0.01%
    {
        _bitSize = CalculateOptimalBitSize(capacity, falsePositiveRate);
        _hashFunctions = CalculateOptimalHashFunctions(capacity, _bitSize);
        _bits = new BitArray(_bitSize);
    }

    public void Add(string item)
    {
        var hashValues = ComputeHashes(item);
        foreach (var hash in hashValues)
        {
            var index = GetBitIndex(hash);
            _bits[index] = true;
        }
    }

    public bool MightContain(string item)
    {
        // First check the bloom filter
        var hashValues = ComputeHashes(item);
        var result = hashValues.All(hash => _bits[GetBitIndex(hash)]);

        if (result)
        {
            // If bloom filter says yes, check recent false positives cache
            lock (_cacheLock)
            {
                if (_recentFalsePositives.Contains(item))
                {
                    return false; // Known false positive
                }
            }
        }
        return result;
    }

    public void AddFalsePositive(string item)
    {
        lock (_cacheLock)
        {
            if (_recentFalsePositives.Count >= CACHE_SIZE)
            {
                _recentFalsePositives.Clear();
            }
            _recentFalsePositives.Add(item);
        }
    }

    private int GetBitIndex(uint hash)
    {
        var index = (int)((long)hash % _bitSize);
        if (index < 0) index += _bitSize;
        return index;
    }

    private uint[] ComputeHashes(string item)
    {
        var results = new uint[_hashFunctions];
        var data = Encoding.UTF8.GetBytes(item);

        using var sha256 = SHA256.Create();
        using var sha512 = SHA512.Create();

        var hash1 = sha256.ComputeHash(data);
        var hash2 = sha512.ComputeHash(data);

        // Use both SHA-256 and SHA-512 for better distribution
        for (int i = 0; i < _hashFunctions; i++)
        {
            var h1 = BitConverter.ToUInt32(hash1, (i * 4) % (hash1.Length - 4));
            var h2 = BitConverter.ToUInt32(hash2, (i * 4) % (hash2.Length - 4));
            results[i] = h1 ^ (h2 << (i % 32)) ^ (h2 >> ((32 - i) % 32));
        }
        return results;
    }

    private static int CalculateOptimalBitSize(int capacity, double falsePositiveRate)
    {
        var size = -1.0 * capacity * Math.Log(falsePositiveRate) / (Math.Log(2) * Math.Log(2));
        return (int)Math.Min(Math.Ceiling(size), int.MaxValue);
    }

    private static int CalculateOptimalHashFunctions(int capacity, int bitSize)
    {
        var hashCount = Math.Round((double)bitSize / capacity * Math.Log(2));
        return (int)Math.Min(hashCount, int.MaxValue);
    }

    // Helper method to estimate memory usage
    public long EstimateSize()
    {
        return (_bitSize + 7) / 8; // Size in bytes
    }

    // Helper method to get current false positive probability
    public double EstimateFalsePositiveRate(int itemCount)
    {
        var k = _hashFunctions;
        var m = _bitSize;
        var n = itemCount;

        return Math.Pow(1 - Math.Exp(-k * n / (double)m), k);
    }
}
