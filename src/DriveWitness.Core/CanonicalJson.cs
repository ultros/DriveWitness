using System.Collections;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace DriveWitness.Core;

/// <summary>Python-compatible sorted ASCII JSON, including lowercase Unicode escapes.</summary>
public static class CanonicalJson
{
    public static byte[] Bytes(object? value) => Encoding.ASCII.GetBytes(String(value));
    public static string String(object? value) { var output = new StringBuilder(); Write(output, value); return output.ToString(); }
    private static string PythonFloat(double number)
    {
        if (!double.IsFinite(number)) throw new ArgumentException("Non-finite canonical number.");
        bool negative = BitConverter.DoubleToInt64Bits(number) < 0;
        if (number == 0) return negative ? "-0.0" : "0.0";
        string raw = Math.Abs(number).ToString("R", CultureInfo.InvariantCulture).ToLowerInvariant();
        int e = raw.IndexOf('e'); int adjustment = e < 0 ? 0 : int.Parse(raw[(e + 1)..], CultureInfo.InvariantCulture);
        string mantissa = e < 0 ? raw : raw[..e]; int dot = mantissa.IndexOf('.');
        if (dot < 0) dot = mantissa.Length;
        string all = mantissa.Replace(".", "", StringComparison.Ordinal); int first = 0;
        while (all[first] == '0') first++;
        int exponent = dot - first - 1 + adjustment; string digits = all[first..].TrimEnd('0');
        string sign = negative ? "-" : "";
        if (exponent is < -4 or >= 16)
            return sign + digits[0] + (digits.Length > 1 ? "." + digits[1..] : "") + "e" + (exponent < 0 ? "-" : "+") + Math.Abs(exponent).ToString("00", CultureInfo.InvariantCulture);
        int position = exponent + 1;
        if (position <= 0) return sign + "0." + new string('0', -position) + digits;
        if (position >= digits.Length) return sign + digits + new string('0', position - digits.Length) + ".0";
        return sign + digits[..position] + "." + digits[position..];
    }
    private static int CompareKeys(string a, string b) => a.AsSpan().IndexOfAnyInRange('\ud800', '\udfff') < 0 && b.AsSpan().IndexOfAnyInRange('\ud800', '\udfff') < 0
        ? string.CompareOrdinal(a, b) : Encoding.UTF8.GetBytes(a).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(b));
    private static void Quote(StringBuilder output, string text)
    {
        output.Append('"');
        foreach (char c in text)
        {
            output.Append(c switch
            {
                '"' => "\\\"", '\\' => "\\\\", '\b' => "\\b", '\f' => "\\f", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t",
                _ when c < 32 || c >= 128 => "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture), _ => c.ToString()
            });
        }
        output.Append('"');
    }
    private static void Write(StringBuilder output, object? value)
    {
        switch (value)
        {
            case null: output.Append("null"); break;
            case string text: Quote(output, text); break;
            case bool boolean: output.Append(boolean ? "true" : "false"); break;
            case JsonElement element:
                switch (element.ValueKind)
                {
                    case JsonValueKind.Object: Write(output, element.EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value)); break;
                    case JsonValueKind.Array: Write(output, element.EnumerateArray().Select(e => (object?)e).ToArray()); break;
                    case JsonValueKind.String: Quote(output, element.GetString()!); break;
                    case JsonValueKind.Number:
                        string raw = element.GetRawText();
                        output.Append(raw.IndexOfAny(['.', 'e', 'E']) >= 0 ? PythonFloat(element.GetDouble()) : raw); break;
                    case JsonValueKind.True: output.Append("true"); break;
                    case JsonValueKind.False: output.Append("false"); break;
                    case JsonValueKind.Null: output.Append("null"); break;
                    default: throw new ArgumentException("Unsupported canonical JSON value.");
                }
                break;
            case IDictionary<string, object?> dictionary:
                output.Append('{'); bool first = true;
                foreach (var pair in dictionary.OrderBy(p => p.Key, Comparer<string>.Create(CompareKeys)))
                { if (!first) output.Append(','); first = false; Quote(output, pair.Key); output.Append(':'); Write(output, pair.Value); }
                output.Append('}'); break;
            case IDictionary dictionary:
                var converted = new Dictionary<string, object?>();
                foreach (DictionaryEntry pair in dictionary) converted.Add(pair.Key as string ?? throw new ArgumentException("Canonical object keys must be strings."), pair.Value);
                Write(output, converted); break;
            case byte[]: throw new ArgumentException("Encode binary evidence as hex/base64 explicitly.");
            case IEnumerable sequence:
                output.Append('['); bool initial = true;
                foreach (var item in sequence) { if (!initial) output.Append(','); initial = false; Write(output, item); }
                output.Append(']'); break;
            case double number: output.Append(PythonFloat(number)); break;
            case float number: output.Append(PythonFloat(number)); break;
            case IFormattable number: output.Append(number.ToString(null, CultureInfo.InvariantCulture)); break;
            default:
                Write(output, JsonSerializer.SerializeToElement(value, ScanOptions.Json)); break;
        }
    }
}
