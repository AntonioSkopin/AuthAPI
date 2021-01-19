using AuthAPI.Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace AuthAPI.Helpers
{
    public class DataContext : DbContext
    {
        protected readonly IConfiguration _configuration;

        public DataContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // Connect to SQL server database
            options.UseSqlServer(_configuration.GetConnectionString("AuthDB"));
        }

        public DbSet<User> Users { get; set; }
    }
}
