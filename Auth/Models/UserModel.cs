using System;

namespace AuthAPI.Auth.Models
{
    public class UserModel
    {
        public Guid Gd { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Username { get; set; }
    }
}
