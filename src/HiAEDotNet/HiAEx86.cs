using Aes = System.Runtime.Intrinsics.X86.Aes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.Intrinsics;
using System.Buffers.Binary;

namespace HiAEDotNet;

// https://datatracker.ietf.org/doc/html/draft-pham-cfrg-hiae-02#section-7
// 'Cycling Index Approach' and 'Intel AES-NI Optimizations' applied
// Skipped 'Batch Processing Optimization' to keep the code simple
// & operator used instead of % for performance
// MemoryMarshal.Cast<> used to try and avoid allocations whilst having readable code
internal sealed class HiAEx86 : IDisposable
{
    private readonly Vector128<byte>[] _s = new Vector128<byte>[HiAE.BlockSize];
    private GCHandle _handle;
    private int _offset;
    private bool _disposed;

    internal static bool IsSupported() => Aes.IsSupported;

    internal HiAEx86(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        _handle = GCHandle.Alloc(_s, GCHandleType.Pinned);
        ReadOnlySpan<byte> constants = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34, 0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8];
        var k = MemoryMarshal.Cast<byte, Vector128<byte>>(key);
        var n = MemoryMarshal.Cast<byte, Vector128<byte>>(nonce);
        var c = MemoryMarshal.Cast<byte, Vector128<byte>>(constants);

        _s[0] = c[0];
        _s[1] = k[1];
        _s[2] = n[0];
        _s[3] = c[0];
        _s[4] = Vector128<byte>.Zero;
        _s[5] = n[0] ^ k[0];
        _s[6] = Vector128<byte>.Zero;
        _s[7] = c[1];
        _s[8] = n[0] ^ k[1];
        _s[9] = Vector128<byte>.Zero;
        _s[10] = k[1];
        _s[11] = c[0];
        _s[12] = c[1];
        _s[13] = k[1];
        _s[14] = Vector128<byte>.Zero;
        _s[15] = c[0] ^ c[1];

        Diffuse(c[0]);

        _s[(9 + _offset) & HiAE.BlockMask] ^= k[0];
        _s[(13 + _offset) & HiAE.BlockMask] ^= k[1];
    }

    internal void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(HiAEx86)); }
        int remainder = associatedData.Length & HiAE.BlockMask;
        Span<byte> padded = stackalloc byte[HiAE.BlockSize];
        if (associatedData.Length >= HiAE.BlockSize) {
            var ad = MemoryMarshal.Cast<byte, Vector128<byte>>(associatedData[..^remainder]);
            for (int i = 0; i < ad.Length; i++) {
                Update(ad[i]);
            }
        }
        if (remainder != 0) {
            padded.Clear();
            associatedData[^remainder..].CopyTo(padded);
            var p = MemoryMarshal.Cast<byte, Vector128<byte>>(padded);
            Update(p[0]);
        }

        remainder = plaintext.Length & HiAE.BlockMask;
        if (plaintext.Length >= HiAE.BlockSize) {
            var ct = MemoryMarshal.Cast<byte, Vector128<byte>>(ciphertext[..^(HiAE.TagSize + remainder)]);
            var msg = MemoryMarshal.Cast<byte, Vector128<byte>>(plaintext[..^remainder]);
            for (int i = 0; i < msg.Length; i++) {
                UpdateEnc(ref ct[i], msg[i]);
            }
        }
        if (remainder != 0) {
            padded.Clear();
            plaintext[^remainder..].CopyTo(padded);
            var p = MemoryMarshal.Cast<byte, Vector128<byte>>(padded);
            UpdateEnc(ref p[0], p[0]);
            padded[..remainder].CopyTo(ciphertext[^(HiAE.TagSize + remainder)..^HiAE.TagSize]);
        }

        var t = MemoryMarshal.Cast<byte, Vector128<byte>>(ciphertext[^HiAE.TagSize..]);
        Finalize(ref t[0], (ulong)associatedData.Length, (ulong)plaintext.Length);
        CryptographicOperations.ZeroMemory(padded);
    }

    internal void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(HiAEx86)); }
        int remainder = associatedData.Length & HiAE.BlockMask;
        Span<byte> padded = stackalloc byte[HiAE.BlockSize];
        if (associatedData.Length >= HiAE.BlockSize) {
            var ad = MemoryMarshal.Cast<byte, Vector128<byte>>(associatedData[..^remainder]);
            for (int i = 0; i < ad.Length; i++) {
                Update(ad[i]);
            }
        }
        if (remainder != 0) {
            padded.Clear();
            associatedData[^remainder..].CopyTo(padded);
            var p = MemoryMarshal.Cast<byte, Vector128<byte>>(padded);
            Update(p[0]);
        }

        remainder = (ciphertext.Length - HiAE.TagSize) & HiAE.BlockMask;
        if (plaintext.Length >= HiAE.BlockSize) {
            var msg = MemoryMarshal.Cast<byte, Vector128<byte>>(plaintext[..^remainder]);
            var ct = MemoryMarshal.Cast<byte, Vector128<byte>>(ciphertext[..^(HiAE.TagSize + remainder)]);
            for (int i = 0; i < ct.Length; i++) {
                UpdateDec(ref msg[i], ct[i]);
            }
        }
        if (remainder != 0) {
            padded.Clear();
            ciphertext[^(HiAE.TagSize + remainder)..^HiAE.TagSize].CopyTo(padded);
            var p = MemoryMarshal.Cast<byte, Vector128<byte>>(padded);

            Span<byte> keystream = stackalloc byte[HiAE.BlockSize];
            var ks = MemoryMarshal.Cast<byte, Vector128<byte>>(keystream);
            ks[0] = Aes.Encrypt(_s[(0 + _offset) & HiAE.BlockMask] ^ _s[(1 + _offset) & HiAE.BlockMask], p[0] ^ _s[(9 + _offset) & HiAE.BlockMask]);
            keystream[remainder..].CopyTo(padded[remainder..]);

            UpdateDec(ref p[0], p[0]);
            padded[..remainder].CopyTo(plaintext[^remainder..]);
        }
        CryptographicOperations.ZeroMemory(padded);

        Span<byte> computedTag = stackalloc byte[HiAE.TagSize];
        var t = MemoryMarshal.Cast<byte, Vector128<byte>>(computedTag);
        Finalize(ref t[0], (ulong)associatedData.Length, (ulong)plaintext.Length);

        if (!CryptographicOperations.FixedTimeEquals(computedTag, ciphertext[^HiAE.TagSize..])) {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(computedTag);
            throw new CryptographicException();
        }
    }

    private void Rol()
    {
        _offset = (_offset + 1) & HiAE.BlockMask;
    }

    private void Update(Vector128<byte> xi)
    {
        int s0 = (0 + _offset) & HiAE.BlockMask;
        int s13 = (13 + _offset) & HiAE.BlockMask;
        var t = Aes.Encrypt(_s[s0] ^ _s[(1 + _offset) & HiAE.BlockMask], xi);
        _s[s0] = Aes.Encrypt(_s[s13], t);
        _s[(3 + _offset) & HiAE.BlockMask] ^= xi;
        _s[s13] ^= xi;
        Rol();
    }

    private void UpdateEnc(ref Vector128<byte> ci, Vector128<byte> mi)
    {
        int s0 = (0 + _offset) & HiAE.BlockMask;
        int s13 = (13 + _offset) & HiAE.BlockMask;
        var t = Aes.Encrypt(_s[s0] ^ _s[(1 + _offset) & HiAE.BlockMask], mi);
        ci = t ^ _s[(9 + _offset) & HiAE.BlockMask];
        _s[s0] = Aes.Encrypt(_s[s13], t);
        _s[(3 + _offset) & HiAE.BlockMask] ^= mi;
        _s[s13] ^= mi;
        Rol();
    }

    private void UpdateDec(ref Vector128<byte> mi, Vector128<byte> ci)
    {
        int s0 = (0 + _offset) & HiAE.BlockMask;
        int s13 = (13 + _offset) & HiAE.BlockMask;
        var t = ci ^ _s[(9 + _offset) & HiAE.BlockMask];
        mi = Aes.Encrypt(_s[s0] ^ _s[(1 + _offset) & HiAE.BlockMask], t);
        _s[s0] = Aes.Encrypt(_s[s13], t);
        _s[(3 + _offset) & HiAE.BlockMask] ^= mi;
        _s[s13] ^= mi;
        Rol();
    }

    private void Diffuse(Vector128<byte> x)
    {
        for (int i = 0; i < 32; i++) {
            Update(x);
        }
    }

    private void Finalize(ref Vector128<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        Span<byte> lengths = stackalloc byte[HiAE.BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], plaintextLength * 8);

        var l = MemoryMarshal.Cast<byte, Vector128<byte>>(lengths);
        Diffuse(l[0]);

        tag = _s[0] ^ _s[1] ^ _s[2] ^ _s[3] ^ _s[4] ^ _s[5] ^ _s[6] ^ _s[7] ^ _s[8] ^ _s[9] ^ _s[10] ^ _s[11] ^ _s[12] ^ _s[13] ^ _s[14] ^ _s[15];
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void Dispose()
    {
        if (_disposed) { return; }
        for (int i = 0; i < _s.Length; i++) {
            _s[i] = Vector128<byte>.Zero;
        }
        _handle.Free();
        _offset = 0;
        _disposed = true;
    }
}
