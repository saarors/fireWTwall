using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    public static class SqlInjectionDetector
    {
        private static readonly (string Name, string Severity, Regex Pattern)[] Rules =
        {
            ("sql-union-select",      "critical", new Regex(@"\bunion\s+(?:all\s+)?select\b",                         RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-drop-table",        "critical", new Regex(@";\s*drop\s+table\b",                                    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-xp-cmdshell",       "critical", new Regex(@"\bxp_cmdshell\b",                                       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-exec",              "critical", new Regex(@"\bexec(?:ute)?\s*\(",                                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-information-schema","critical", new Regex(@"\binformation_schema\b",                                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-sleep",             "critical", new Regex(@"\bsleep\s*\(\s*\d",                                     RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-benchmark",         "critical", new Regex(@"\bbenchmark\s*\(",                                      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-load-file",         "critical", new Regex(@"\bload_file\s*\(",                                      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-into-outfile",      "critical", new Regex(@"\binto\s+(?:out|dump)file\b",                          RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-sys-tables",        "critical", new Regex(@"\bsysobjects\b|\bsyscolumns\b",                        RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-comment",           "high",     new Regex(@"(?:--|/\*|\*/|#\s*$)",                                 RegexOptions.Multiline  | RegexOptions.Compiled)),
            ("sql-stacked-query",     "high",     new Regex(@";\s*(?:select|insert|update|delete|drop|alter|create|exec)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-cast-convert",      "high",     new Regex(@"\b(?:cast|convert)\s*\(",                              RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-char-concat",       "high",     new Regex(@"\bchar\s*\(\s*\d",                                     RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-boolean-true",      "medium",   new Regex(@"\bor\s+['""\d]+\s*=\s*['""\d]+",                      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-boolean-and",       "medium",   new Regex(@"\band\s+['""\d]+\s*=\s*['""\d]+",                     RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-order-by-num",      "medium",   new Regex(@"\border\s+by\s+\d+\b",                                 RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-tautology",         "medium",   new Regex(@"'\s*or\s*'[^']*'\s*=\s*'",                            RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-waitfor-delay",     "critical", new Regex(@"\bwaitfor\s+delay\b",                                  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-pg-sleep",          "critical", new Regex(@"\bpg_sleep\s*\(",                                      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-hex-values",        "medium",   new Regex(@"0x[0-9a-f]{4,}",                                       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-group-by-having",   "medium",   new Regex(@"\bhaving\s+\d+\s*=\s*\d+",                            RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-dbms-fingerprint",  "medium",   new Regex(@"\b(?:@@version|version\s*\(\s*\)|user\s*\(\s*\)|database\s*\(\s*\))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-declare-set",       "high",     new Regex(@"\bdeclare\s+@\w+\b",                                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-bulk-insert",       "critical", new Regex(@"\bbulk\s+insert\b",                                    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-openrowset",        "critical", new Regex(@"\bopenrowset\s*\(",                                     RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-case-when",         "high",     new Regex(@"CASE\s+WHEN\s+.*\s+THEN",                             RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-extractvalue",      "critical", new Regex(@"EXTRACTVALUE\s*\(",                                    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-updatexml",         "critical", new Regex(@"UPDATEXML\s*\(",                                       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-gtid",              "critical", new Regex(@"GTID_SUBSET\s*\(",                                     RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-exp-tilde",         "critical", new Regex(@"exp\(~\(",                                             RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-polygon",           "high",     new Regex(@"(polygon|geometrycollection|linestring|multipoint)\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-procedure-analyse", "high",     new Regex(@"procedure\s+analyse\s*\(",                             RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sql-dbms-version",      "critical", new Regex(@"@@version|@@global|@@session",                        RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        };

        public static DetectorResult Scan(Dictionary<string, string> sources)
        {
            foreach (var kv in sources)
            {
                var r = MatchString(kv.Value, kv.Key);
                if (r != null) return r;
            }
            return null;
        }

        private static DetectorResult MatchString(string value, string label)
        {
            foreach (var rule in Rules)
            {
                Match m = rule.Pattern.Match(value);
                if (m.Success)
                    return new DetectorResult(rule.Name, rule.Severity,
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value, label);
            }
            return null;
        }
    }
}
