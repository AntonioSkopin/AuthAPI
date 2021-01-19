using AuthAPI.Auth.Entities;
using AuthAPI.Helpers;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AuthAPI.Auth.Services
{
    public interface IAuthService
    {
        User Authenticate(string username, string password);
        Task<User> Register(User user, string password);
        Task<User> GetByGd(Guid gd);
        Task Update(User user, string password = null);
        Task Delete(int id);
    }

    public class AuthService : IAuthService
    {
        protected DataContext _context;

        public AuthService(DataContext context)
        {
            _context = context;
        }

        public User Authenticate(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                throw new AppException("Please enter your username & password.");

            var user = _context.Users.SingleOrDefault(usr => usr.Username == username);

            // Check if username exists
            if (user == null)
                return null;

            // Check if password is correct
            if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
                return null;

            // Authentication successful
            return user;
        }

        public async Task<User> Register(User user, string password)
        {
            // Validation
            if (string.IsNullOrWhiteSpace(password))
                throw new AppException("Password is required");

            if (_context.Users.Any(usr => usr.Username == user.Username))
                throw new AppException("Username \"" + user.Username + "\" is already taken");

            byte[] passwordHash, passwordSalt;
            CreatePasswordHash(password, out passwordHash, out passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();

            return user;
        }

        public async Task Delete(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user != null)
            {
                _context.Users.Remove(user);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<User> GetByGd(Guid gd)
        {
            return await _context.Users.FindAsync(gd);
        }

        public async Task Update(User userParam, string password = null)
        {
            var user = await _context.Users.FindAsync(userParam.Gd);

            if (user == null)
                throw new AppException("User not found");

            // Update username if it has changed
            if (!string.IsNullOrWhiteSpace(userParam.Username) && userParam.Username != user.Username)
            {
                // Throw error if the new username is already taken
                if (_context.Users.Any(usr => usr.Username == userParam.Username))
                    throw new AppException("Username " + userParam.Username + " is already taken");

                user.Username = userParam.Username;
            }

            // Update user properties if provided
            if (!string.IsNullOrWhiteSpace(userParam.Firstname))
                user.Firstname = userParam.Firstname;

            if (!string.IsNullOrWhiteSpace(userParam.Lastname))
                user.Lastname = userParam.Lastname;

            // Update password if provided
            if (!string.IsNullOrWhiteSpace(password))
            {
                byte[] passwordHash, passwordSalt;
                CreatePasswordHash(password, out passwordHash, out passwordSalt);

                user.PasswordHash = passwordHash;
                user.PasswordSalt = passwordSalt;
            }

            _context.Users.Update(user);
            await _context.SaveChangesAsync();
        }

        // Private helper methods
        private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            // Validation
            if (password == null)
                throw new ArgumentNullException("password");

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Value cannot be empty or whitespace only string.", "password");

            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private static bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            // Validation:
            if (password == null)
                throw new ArgumentNullException("password");

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Value cannot be empty or whitespace only string.", "password");

            if (storedHash.Length != 64)
                throw new ArgumentException("Invalid length of password hash (64 bytes expected).", "passwordHash");

            if (storedSalt.Length != 128)
                throw new ArgumentException("Invalid length of password salt (128 bytes expected).", "passwordHash");

            using (var hmac = new System.Security.Cryptography.HMACSHA512(storedSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != storedHash[i]) return false;
                }
            }

            return true;
        }
    }
}
