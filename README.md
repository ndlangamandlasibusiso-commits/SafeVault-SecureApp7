# SafeVault-SecureApp4
SafeVault-SecureApp/
│
├── Program.cs
├── Database.cs
├── AuthService.cs
├── Validation.cs
├── Security.cs
├── Tests.cs
├── README.md 

using System;

class Program
{
    static void Main()
    {
        Console.WriteLine("=== SafeVault Login ===");

        Console.Write("Username: ");
        string username = Console.ReadLine();

        Console.Write("Password: ");
        string password = Console.ReadLine();

        if (!Validation.IsValidInput(username) || !Validation.IsValidInput(password))
        {
            Console.WriteLine("Invalid input!");
            return;
        }

        var user = AuthService.Login(username, password);

        if (user == null)
        {
            Console.WriteLine("Login failed.");
            return;
        }

        Console.WriteLine($"Welcome {user.Username}! Role: {user.Role}");

        if (user.Role == "Admin")
        {
            Console.WriteLine("Access granted to admin panel.");
        }
        else
        {
            Console.WriteLine("Standard user access.");
        }
    }
}

using System.Data.SqlClient;

public class User
{
    public string Username { get; set; }
    public string Role { get; set; }
}

public class AuthService
{
    public static User Login(string username, string password)
    {
        using (SqlConnection conn = Database.GetConnection())
        {
            conn.Open();

            string query = "SELECT Username, Role FROM Users WHERE Username=@u AND Password=@p";

            SqlCommand cmd = new SqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@u", username);
            cmd.Parameters.AddWithValue("@p", password);

            var reader = cmd.ExecuteReader();

            if (reader.Read())
            {
                return new User
                {
                    Username = reader["Username"].ToString(),
                    Role = reader["Role"].ToString()
                };
            }
        }

        return null;
    }
}

using System.Text.RegularExpressions;

public class Validation
{
    public static bool IsValidInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return false;

        if (input.Length > 50)
            return false;

        // Only letters and numbers
        return Regex.IsMatch(input, "^[a-zA-Z0-9]+$");
    }
}

using System.Web;

public class Security
{
    public static string Sanitize(string input)
    {
        return HttpUtility.HtmlEncode(input);
    }
}

using System;

public class Tests
{
    public static void Run()
    {
        Console.WriteLine("Running tests...");

        // Input validation tests
        Console.WriteLine(Validation.IsValidInput("") == false ? "Pass" : "Fail");
        Console.WriteLine(Validation.IsValidInput("User123") == true ? "Pass" : "Fail");

        // XSS test
        string attack = "<script>alert(1)</script>";
        string safe = Security.Sanitize(attack);

        Console.WriteLine(safe.Contains("<") ? "Fail" : "Pass");

        Console.WriteLine("Tests complete ");
    }
}