using HSalsa20DotNet;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HSalsa20DotNetTests;

[TestClass]
public class HSalsa20Tests
{
    // https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
    [TestMethod]
    [DataRow("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "00000000000000000000000000000000", "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")]
    [DataRow("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389", "69696ee955b62b73cd62bda875fc73d6", "dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4")]
    [DataRow("ee304fca27008d8c126f90027901d80f7f1d8b8dc936cf3b9f819692827e5777", "81918ef2a5e0da9b3e9060521e4bb352", "bc1b30fc072cc14075e4baa731b5a845ea9b11e9a5191f94e18cba8fd821a7cd")]
    public void TestVectors(string key, string nonce, string output)
    {
        Span<byte> o = stackalloc byte[HSalsa20.OutputSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> n = Convert.FromHexString(nonce);
        
        HSalsa20.DeriveKey(o, k, n);
        
        Assert.AreEqual(output, Convert.ToHexString(o).ToLower());
    }
}