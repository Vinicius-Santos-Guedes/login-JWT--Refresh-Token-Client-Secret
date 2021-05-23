using AuthJwt.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthJwt.Repositories
{
    public static class UserRepository
    {
        public static List<User> users { get; } = new List<User>() {
        new User { Id = new System.Guid(), UserName = "batman", Password = "batman", Roles = new List<Role>() { new Role { Display = "manager" }, new Role { Display = "networker" }, new Role { Display = "advisor" } } },
        new User { Id = new System.Guid(), UserName = "robin", Password = "robin", Roles = new List<Role>() { new Role { Display = "employee" } } }
        };

    }
}
