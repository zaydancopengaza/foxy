using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

// Compile (C# 5 / .NET 4.x):
//   "build1 (2).exe" /noconfig /optimize+ /r:System.dll /r:System.Core.dll /r:System.DirectoryServices.dll /target:library /out:certaudit.dll certaudit.cs
//
// Full scan:
//   $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes(".\certaudit.dll"))
//   $asm.GetType("CertAudit").GetMethod("Run", [type[]]@([string])).Invoke($null, @("10.2.1.22"))
//
// Targeted PoC:
//   $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes(".\certaudit.dll"))
//   $asm.GetType("CertAudit").GetMethod("RunTargeted").Invoke($null, @("10.2.1.22","mcx-DCSRV02-CA","WinRMOverSSL"))

public class CertAudit {

    static readonly Dictionary<string,string> EKU_NAMES = new Dictionary<string,string> {
        {"1.3.6.1.5.5.7.3.2",        "Client Authentication"},
        {"1.3.6.1.4.1.311.20.2.2",   "Smart Card Logon"},
        {"2.5.29.37.0",               "Any Purpose"},
        {"1.3.6.1.4.1.311.20.2.1",   "Certificate Request Agent"},
        {"1.3.6.1.5.5.7.3.1",        "Server Authentication"},
        {"1.3.6.1.5.5.7.3.4",        "Secure Email"},
        {"1.3.6.1.4.1.311.10.3.4",   "Encrypting File System"},
    };

    static readonly HashSet<string> AUTH_EKUS = new HashSet<string> {
        "1.3.6.1.5.5.7.3.2",
        "1.3.6.1.4.1.311.20.2.2",
        "2.5.29.37.0",
        "1.3.6.1.4.1.311.20.2.1",
    };

    const int FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
    const int ENROLL_FLAG_PEND_ALL_REQUESTS  = 0x00000002;

    const string GUID_ENROLL     = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
    const string GUID_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";

    static string dcPrefix   = "";
    static string configNC   = "";
    static string domainNC   = "";
    static string domainSID  = "";

    static Dictionary<string,string>       caHosts     = new Dictionary<string,string>();
    static Dictionary<string,List<string>> caTemplates = new Dictionary<string,List<string>>();

    // =====================================================================
    //  Entry points
    // =====================================================================

    public static void Run() {
        Run("");
    }

    public static void Run(string dcIP) {
        Init(dcIP);
        if (!Bootstrap()) return;
        EnumCAs();
        AuditTemplates(null, null);
    }

    // RunAll — prints every template including patched/non-vulnerable ones
    // Use this for PoC evidence when the finding has been remediated
    public static void RunAll(string dcIP) {
        Init(dcIP);
        if (!Bootstrap()) return;
        EnumCAs();
        AuditTemplatesAll(null, null);
    }

    // RunAllTargeted — all fields for one specific CA + template, vuln or not
    public static void RunAllTargeted(string dcIP, string caName, string templateName) {
        Init(dcIP);
        if (!Bootstrap()) return;
        EnumCAs();
        Console.WriteLine("");
        Console.WriteLine("CertAudit - Full Template Dump (PoC Mode)");
        Console.WriteLine("  CA       : " + caName);
        Console.WriteLine("  Template : " + templateName);
        Console.WriteLine("  DC       : " + dcIP);
        Console.WriteLine("  Time     : " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        Console.WriteLine("");
        Console.WriteLine(new string('=', 64));
        AuditTemplatesAll(caName, templateName);
    }

    public static void RunTargeted(string dcIP, string caName, string templateName) {
        Init(dcIP);
        if (!Bootstrap()) return;
        EnumCAs();

        Console.WriteLine("");
        Console.WriteLine("CertAudit - Targeted PoC");
        Console.WriteLine("  CA       : " + caName);
        Console.WriteLine("  Template : " + templateName);
        Console.WriteLine("  DC       : " + dcIP);
        Console.WriteLine("  Time     : " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        Console.WriteLine("");
        Console.WriteLine(new string('=', 64));

        AuditTemplates(caName, templateName);
    }

    // =====================================================================
    //  Init / Bootstrap
    // =====================================================================

    static void Init(string dcIP) {
        dcPrefix    = string.IsNullOrEmpty(dcIP) ? "" : dcIP + "/";
        configNC    = "";
        domainNC    = "";
        domainSID   = "";
        caHosts     = new Dictionary<string,string>();
        caTemplates = new Dictionary<string,List<string>>();
    }

    static bool Bootstrap() {
        try {
            string rootDsePath = "LDAP://" + dcPrefix + "RootDSE";
            using (var root = new DirectoryEntry(rootDsePath, null, null, AuthenticationTypes.None)) {
                object cfgVal = root.Properties["configurationNamingContext"].Value;
                object domVal = root.Properties["defaultNamingContext"].Value;
                configNC = cfgVal != null ? cfgVal.ToString() : "";
                domainNC = domVal != null ? domVal.ToString() : "";
            }

            if (string.IsNullOrEmpty(configNC)) {
                Console.WriteLine("[!] Cannot read configNC from RootDSE");
                return false;
            }

            string domPath = "LDAP://" + dcPrefix + domainNC;
            using (var dom = new DirectoryEntry(domPath, null, null, AuthenticationTypes.None)) {
                byte[] sid = dom.Properties["objectSid"].Value as byte[];
                if (sid != null)
                    domainSID = new SecurityIdentifier(sid, 0).ToString();
            }

            Console.WriteLine("[*] Domain : " + domainNC);
            Console.WriteLine("[*] Config : " + configNC);
            return true;
        } catch (Exception ex) {
            Console.WriteLine("[!] Bootstrap failed: " + ex.Message);
            return false;
        }
    }

    // =====================================================================
    //  CA Enumeration
    // =====================================================================

    static void EnumCAs() {
        string caPath = "LDAP://" + dcPrefix +
            "CN=Enrollment Services,CN=Public Key Services,CN=Services," + configNC;
        try {
            using (var caBase = new DirectoryEntry(caPath, null, null, AuthenticationTypes.None)) {
                using (var search = new DirectorySearcher(caBase)) {
                    search.Filter = "(objectClass=pKIEnrollmentService)";
                    search.PropertiesToLoad.AddRange(new string[] { "cn", "dNSHostName", "certificateTemplates" });
                    search.PageSize = 1000;

                    foreach (SearchResult r in search.FindAll()) {
                        string name = GetStr(r, "cn");
                        string host = GetStr(r, "dNSHostName");
                        caHosts[name] = host;
                        caTemplates[name] = new List<string>();

                        ResultPropertyValueCollection tv = r.Properties["certificateTemplates"];
                        if (tv != null) {
                            foreach (object o in tv) {
                                if (o != null) {
                                    string tn = o.ToString();
                                    if (!string.IsNullOrEmpty(tn))
                                        caTemplates[name].Add(tn);
                                }
                            }
                        }

                        Console.WriteLine("[*] CA : " + name + " @ " + host +
                                          " (" + caTemplates[name].Count + " templates)");
                    }
                }
            }
        } catch (Exception ex) {
            Console.WriteLine("[!] CA enum error: " + ex.Message);
        }
        Console.WriteLine("");
    }

    // =====================================================================
    //  Template Audit
    // =====================================================================

    // Wrapper: vulnerable-only output (original behaviour)
    static void AuditTemplates(string filterCA, string filterTemplate) {
        AuditTemplatesCore(filterCA, filterTemplate, false);
    }

    // Wrapper: all templates regardless of vuln state
    static void AuditTemplatesAll(string filterCA, string filterTemplate) {
        AuditTemplatesCore(filterCA, filterTemplate, true);
    }

    static void AuditTemplatesCore(string filterCA, string filterTemplate, bool showAll) {
        string ldapFilter = string.IsNullOrEmpty(filterTemplate)
            ? "(objectClass=pKICertificateTemplate)"
            : "(&(objectClass=pKICertificateTemplate)(cn=" + filterTemplate + "))";

        string tmplPath = "LDAP://" + dcPrefix +
            "CN=Certificate Templates,CN=Public Key Services,CN=Services," + configNC;

        int found = 0;
        try {
            using (var tmplBase = new DirectoryEntry(tmplPath, null, null, AuthenticationTypes.None)) {
                using (var search = new DirectorySearcher(tmplBase)) {
                    search.Filter = ldapFilter;
                    search.PropertiesToLoad.AddRange(new string[] {
                        "cn", "displayName",
                        "msPKI-Certificate-Name-Flag",
                        "msPKI-Enrollment-Flag",
                        "msPKI-RA-Signature",
                        "msPKI-Minimal-Key-Size",
                        "pKIExtendedKeyUsage",
                        "msPKI-Certificate-Application-Policy",
                        "pKIExpirationPeriod",
                        "pKIOverlapPeriod",
                        "nTSecurityDescriptor"
                    });
                    search.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
                    search.PageSize = 1000;

                    foreach (SearchResult r in search.FindAll()) {
                        string name        = GetStr(r, "cn");
                        string displayName = GetStr(r, "displayName");

                        int nameFlag    = GetInt(r, "msPKI-Certificate-Name-Flag");
                        int enrollFlag  = GetInt(r, "msPKI-Enrollment-Flag");
                        int raSignature = GetInt(r, "msPKI-RA-Signature");
                        int minKeySize  = GetInt(r, "msPKI-Minimal-Key-Size");

                        List<string> ekus = GetStrList(r, "pKIExtendedKeyUsage");
                        if (ekus.Count == 0)
                            ekus = GetStrList(r, "msPKI-Certificate-Application-Policy");

                        bool managerApproval  = (enrollFlag & ENROLL_FLAG_PEND_ALL_REQUESTS) != 0;
                        bool enrolleeSupplies = (nameFlag & FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0;
                        bool hasAuthEKU       = HasAuthEKU(ekus);

                        List<string> publishedOn = GetPublishingCAs(name);
                        bool isEnabled = publishedOn.Count > 0;

                        if (!string.IsNullOrEmpty(filterCA)) {
                            bool caMatch = false;
                            foreach (string p in publishedOn) {
                                if (p.StartsWith(filterCA, StringComparison.OrdinalIgnoreCase)) {
                                    caMatch = true;
                                    break;
                                }
                            }
                            if (!caMatch && isEnabled) {
                                Console.WriteLine("[!] Template '" + name + "' exists but is NOT published on " + filterCA);
                                Console.WriteLine("    Published on: " +
                                    (publishedOn.Count > 0 ? string.Join(", ", publishedOn.ToArray()) : "(none)"));
                            }
                        }

                        AclResult acl = ParseACL(r, name);

                        bool esc1 = isEnabled
                                 && enrolleeSupplies
                                 && !managerApproval
                                 && raSignature == 0
                                 && hasAuthEKU
                                 && acl.LowPrivCanEnroll;

                        bool esc4 = isEnabled && acl.WriteFindings.Count > 0;

                        if (!showAll && !esc1 && !esc4) continue;

                        found++;

                        List<string> vulns = new List<string>();
                        if (esc1) vulns.Add("ESC1");
                        if (esc4) vulns.Add("ESC4");

                        string pubStr = publishedOn.Count > 0
                            ? string.Join(", ", publishedOn.ToArray())
                            : "(not published)";

                        Console.WriteLine("");
                        Console.WriteLine("  Template Name                : " + name);
                        Console.WriteLine("  Display Name                 : " + displayName);
                        Console.WriteLine("  Certificate Authorities      : " + pubStr);
                        Console.WriteLine("  Enabled                      : " + isEnabled);
                        Console.WriteLine("  Client Authentication        : " + hasAuthEKU);
                        Console.WriteLine("  Enrollment Agent             : " +
                            (ekus.Contains("1.3.6.1.4.1.311.20.2.1") ? "True" : "False"));
                        Console.WriteLine("  Any Purpose                  : " +
                            (ekus.Contains("2.5.29.37.0") || ekus.Count == 0 ? "True" : "False"));
                        Console.WriteLine("  Enrollee Supplies Subject    : " + enrolleeSupplies);
                        Console.WriteLine("  Certificate Name Flag        : 0x" + nameFlag.ToString("X8") +
                            (enrolleeSupplies ? " (ENROLLEE_SUPPLIES_SUBJECT)" : ""));
                        Console.WriteLine("  Enrollment Flag              : 0x" + enrollFlag.ToString("X4"));
                        Console.WriteLine("  Requires Manager Approval    : " + managerApproval);
                        Console.WriteLine("  Authorized Signatures Req.   : " + raSignature);
                        Console.WriteLine("  Minimum RSA Key Length       : " + minKeySize);
                        Console.WriteLine("  Extended Key Usage           : " + EKUStr(ekus));
                        Console.WriteLine("  Validity Period              : " + DecodeFiletime(r, "pKIExpirationPeriod"));
                        Console.WriteLine("  Renewal Period               : " + DecodeFiletime(r, "pKIOverlapPeriod"));
                        Console.WriteLine("  Permissions");
                        Console.WriteLine("    Enrollment Permissions");

                        if (acl.EnrollSIDs.Count > 0) {
                            foreach (string s in acl.EnrollSIDs)
                                Console.WriteLine("      Enrollment Rights        : " + s);
                        } else {
                            Console.WriteLine("      Enrollment Rights        : (none resolved)");
                        }

                        if (acl.WriteFindings.Count > 0) {
                            Console.WriteLine("    Write Permissions (ESC4)");
                            foreach (string wf in acl.WriteFindings)
                                Console.WriteLine("      " + wf);
                        }

                        if (vulns.Count > 0) {
                            Console.WriteLine("  [!!!] Vulnerabilities         : " + string.Join(", ", vulns.ToArray()));
                            if (esc1) {
                                Console.WriteLine("        ESC1 Details:");
                                Console.WriteLine("          msPKI-Certificate-Name-Flag has CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT.");
                                Console.WriteLine("          A low-privilege principal can request a certificate and supply");
                                Console.WriteLine("          an arbitrary Subject Alternative Name (UPN/DNS).");
                                Console.WriteLine("          With Client Authentication EKU this certificate can be used");
                                Console.WriteLine("          to authenticate as any domain principal including Domain Admins.");
                                Console.WriteLine("          Requires: Enrollment right for Domain Users / Authenticated Users.");
                            }
                            if (esc4) {
                                Console.WriteLine("        ESC4 Details:");
                                Console.WriteLine("          A low-privilege principal has write permissions on the template ACL.");
                                Console.WriteLine("          This allows modifying the template to introduce ESC1 or other");
                                Console.WriteLine("          misconfigurations without requiring CA administrator privileges.");
                            }
                        } else {
                            Console.WriteLine("  Vulnerabilities              : None Detected");
                        }

                        Console.WriteLine("");
                        Console.WriteLine(new string('-', 64));
                    }
                }
            }
        } catch (Exception ex) {
            Console.WriteLine("[!] Template query error: " + ex.Message);
        }

        if (found == 0 && !string.IsNullOrEmpty(filterTemplate))
            Console.WriteLine("[!] Template '" + filterTemplate + "' not found in AD.");
        else
            Console.WriteLine("[*] Done. Templates printed: " + found);
    }

    // =====================================================================
    //  ACL Parsing
    // =====================================================================

    class AclResult {
        public bool LowPrivCanEnroll      = false;
        public List<string> EnrollSIDs    = new List<string>();
        public List<string> WriteFindings = new List<string>();
    }

    static AclResult ParseACL(SearchResult r, string templateName) {
        var result  = new AclResult();
        var lowPriv = BuildLowPrivSIDSet();

        try {
            ResultPropertyValueCollection adspathProp = r.Properties["adspath"];
            string dn = "";
            if (adspathProp != null && adspathProp.Count > 0 && adspathProp[0] != null)
                dn = adspathProp[0].ToString();

            if (string.IsNullOrEmpty(dn)) return result;

            if (!string.IsNullOrEmpty(dcPrefix))
                dn = dn.Replace("LDAP://", "LDAP://" + dcPrefix);

            using (var entry = new DirectoryEntry(dn, null, null, AuthenticationTypes.None)) {
                entry.RefreshCache(new string[] { "nTSecurityDescriptor" });
                AuthorizationRuleCollection rules = entry.ObjectSecurity.GetAccessRules(
                    true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule rule in rules) {
                    if (rule.AccessControlType != AccessControlType.Allow) continue;

                    string sid     = rule.IdentityReference.ToString();
                    if (IsPrivilegedSID(sid)) continue;

                    bool isLowPriv = lowPriv.Contains(sid);
                    ActiveDirectoryRights rights = rule.ActiveDirectoryRights;
                    string objGuid = rule.ObjectType.ToString().ToLower();

                    bool enroll =
                        ((rights & ActiveDirectoryRights.ExtendedRight) != 0 &&
                         (objGuid == GUID_ENROLL ||
                          objGuid == GUID_AUTOENROLL ||
                          objGuid == "00000000-0000-0000-0000-000000000000"))
                        || ((rights & ActiveDirectoryRights.GenericAll) != 0);

                    if (enroll) {
                        string display = TryResolveSID(sid);
                        result.EnrollSIDs.Add(display);
                        if (isLowPriv) result.LowPrivCanEnroll = true;
                    }

                    if (!isLowPriv) continue;

                    string rightDesc = "";
                    if      ((rights & ActiveDirectoryRights.GenericAll)   != 0) rightDesc = "GenericAll";
                    else if ((rights & ActiveDirectoryRights.GenericWrite)  != 0) rightDesc = "GenericWrite";
                    else if ((rights & ActiveDirectoryRights.WriteOwner)    != 0) rightDesc = "WriteOwner";
                    else if ((rights & ActiveDirectoryRights.WriteDacl)     != 0) rightDesc = "WriteDacl";
                    else if ((rights & ActiveDirectoryRights.WriteProperty) != 0) rightDesc = "WriteProperty";

                    if (!string.IsNullOrEmpty(rightDesc))
                        result.WriteFindings.Add(TryResolveSID(sid) + " (" + sid + ") : " + rightDesc);
                }
            }
        } catch (Exception ex) {
            result.WriteFindings.Add("ACL read error: " + ex.Message);
        }

        return result;
    }

    // =====================================================================
    //  Helpers
    // =====================================================================

    static HashSet<string> BuildLowPrivSIDSet() {
        var s = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        s.Add("S-1-1-0");   // Everyone
        s.Add("S-1-5-11");  // Authenticated Users
        s.Add("S-1-5-4");   // Interactive
        if (!string.IsNullOrEmpty(domainSID)) {
            s.Add(domainSID + "-513");  // Domain Users
            s.Add(domainSID + "-515");  // Domain Computers
        }
        return s;
    }

    static bool IsPrivilegedSID(string sid) {
        if (string.IsNullOrEmpty(sid)) return true;
        string[] exact = new string[] { "S-1-5-18", "S-1-5-32-544", "S-1-3-0" };
        foreach (string p in exact)
            if (string.Equals(sid, p, StringComparison.OrdinalIgnoreCase)) return true;
        string[] suffixes = new string[] { "-512","-519","-518","-516","-517","-520","-526","-527" };
        foreach (string suffix in suffixes)
            if (sid.EndsWith(suffix)) return true;
        return false;
    }

    static List<string> GetPublishingCAs(string templateName) {
        var list = new List<string>();
        foreach (KeyValuePair<string,List<string>> kv in caTemplates) {
            foreach (string t in kv.Value) {
                if (string.Equals(t, templateName, StringComparison.OrdinalIgnoreCase)) {
                    string host = caHosts.ContainsKey(kv.Key) ? caHosts[kv.Key] : "?";
                    list.Add(kv.Key + " (" + host + ")");
                    break;
                }
            }
        }
        return list;
    }

    static bool HasAuthEKU(List<string> ekus) {
        if (ekus.Count == 0) return true;
        foreach (string e in ekus)
            if (AUTH_EKUS.Contains(e)) return true;
        return false;
    }

    static string EKUStr(List<string> ekus) {
        if (ekus.Count == 0) return "Any Purpose";
        var parts = new List<string>();
        foreach (string e in ekus) {
            string name;
            parts.Add(EKU_NAMES.TryGetValue(e, out name) ? name : e);
        }
        return string.Join(", ", parts.ToArray());
    }

    static string DecodeFiletime(SearchResult r, string prop) {
        try {
            ResultPropertyValueCollection v = r.Properties[prop];
            if (v == null || v.Count == 0) return "unknown";
            byte[] b = v[0] as byte[];
            if (b == null || b.Length < 8) return "unknown";
            long raw   = BitConverter.ToInt64(b, 0);
            if (raw == 0) return "0 days";
            long ticks  = -raw;
            long years  = ticks / (TimeSpan.TicksPerDay * 365);
            long months = (ticks % (TimeSpan.TicksPerDay * 365)) / (TimeSpan.TicksPerDay * 30);
            long days   = (ticks % (TimeSpan.TicksPerDay * 30)) / TimeSpan.TicksPerDay;
            if (years  > 0) return years  + (years  == 1 ? " year"  : " years");
            if (months > 0) return months + (months == 1 ? " month" : " months");
            return days + (days == 1 ? " day" : " days");
        } catch {
            return "unknown";
        }
    }

    static string TryResolveSID(string sid) {
        try {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
        } catch {
            return sid;
        }
    }

    static string GetStr(SearchResult r, string prop) {
        try {
            ResultPropertyValueCollection v = r.Properties[prop];
            if (v == null || v.Count == 0) return "";
            object o = v[0];
            return o != null ? o.ToString() : "";
        } catch {
            return "";
        }
    }

    static int GetInt(SearchResult r, string prop) {
        try {
            ResultPropertyValueCollection v = r.Properties[prop];
            if (v == null || v.Count == 0) return 0;
            return Convert.ToInt32(v[0]);
        } catch {
            return 0;
        }
    }

    static List<string> GetStrList(SearchResult r, string prop) {
        var list = new List<string>();
        try {
            ResultPropertyValueCollection v = r.Properties[prop];
            if (v == null) return list;
            foreach (object o in v)
                if (o != null) list.Add(o.ToString());
        } catch { }
        return list;
    }
}
