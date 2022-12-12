/*
    HSalsa20.NET: A .NET implementation of HSalsa20.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace HSalsa20DotNet;

public static class HSalsa20
{
    public const int OutputSize = 32;
    public const int KeySize = 32;
    public const int NonceSize = 16;
    
    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> nonce)
    {
        if (outputKeyingMaterial.Length != OutputSize) { throw new ArgumentOutOfRangeException(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, $"{nameof(outputKeyingMaterial)} must be {OutputSize} bytes long."); }
        if (inputKeyingMaterial.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(inputKeyingMaterial), inputKeyingMaterial.Length, $"{nameof(inputKeyingMaterial)} must be {KeySize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        
        uint x0 = 0x61707865;
        uint x5 = 0x3320646e;
        uint x10 = 0x79622d32;
        uint x15 = 0x6b206574;
        uint x1 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 0);
        uint x2 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 4);
        uint x3 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 8);
        uint x4 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 12);
        uint x11 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 16);
        uint x12 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 20);
        uint x13 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 24);
        uint x14 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 28);
        uint x6 = ReadUInt32LittleEndian(nonce, offset: 0);
        uint x7 = ReadUInt32LittleEndian(nonce, offset: 4);
        uint x8 = ReadUInt32LittleEndian(nonce, offset: 8);
        uint x9 = ReadUInt32LittleEndian(nonce, offset: 12);
        
        for (int i = 0; i < 10; i++) {
            QuarterRound(ref x0, ref x4, ref x8, ref x12);
            QuarterRound(ref x5, ref x9, ref x13, ref x1);
            QuarterRound(ref x10, ref x14, ref x2, ref x6);
            QuarterRound(ref x15, ref x3, ref x7, ref x11);
            QuarterRound(ref x0, ref x1, ref x2, ref x3);
            QuarterRound(ref x5, ref x6, ref x7, ref x4);
            QuarterRound(ref x10, ref x11, ref x8, ref x9);
            QuarterRound(ref x15, ref x12, ref x13, ref x14);
        }
        
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 0, x0);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 4, x5);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 8, x10);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 12, x15);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 16, x6);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 20, x7);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 24, x8);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 28, x9);
    }
    
    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> source, int offset)
    {
        return source[offset] | (uint) source[offset + 1] << 8 | (uint) source[offset + 2] << 16 | (uint) source[offset + 3] << 24;
    }
    
    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        b ^= RotateLeft(a + d, 7);
        c ^= RotateLeft(b + a, 9);
        d ^= RotateLeft(c + b, 13);
        a ^= RotateLeft(d + c, 18);
    }
    
    private static uint RotateLeft(uint a, int b)
    {
        return (a << b) | (a >> (32 - b));
    }
    
    private static void WriteUInt32LittleEndian(Span<byte> destination, int offset, uint value)
    {
        destination[offset] = (byte) value;
        destination[offset + 1] = (byte) (value >> 8);
        destination[offset + 2] = (byte) (value >> 16);
        destination[offset + 3] = (byte) (value >> 24);
    }
}