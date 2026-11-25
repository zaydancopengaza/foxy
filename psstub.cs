using System;
using System.IO;
using System.Reflection;

class L {
    static void Main() {
        string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        byte[] raw = File.ReadAllBytes(Path.Combine(dir, "psrun.dll"));
        Assembly asm = Assembly.Load(raw);
        asm.GetType("PS")
           .GetMethod("Run", BindingFlags.Public | BindingFlags.Static)
           .Invoke(null, null);
    }
}