namespace ModScanner.Core;

internal static class Plural
{
    public static string Of(int n, string one, string few, string many)
    {
        int m10 = n % 10, m100 = n % 100;
        string w = m10 == 1 && m100 != 11 ? one
                 : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few
                 : many;
        return $"{n} {w}";
    }
    public static string Cls(int n) => Of(n, "класс", "класса", "классов");
}
