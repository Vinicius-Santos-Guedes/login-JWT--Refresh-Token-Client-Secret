using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AuthJwt.Models
{
    public class User
    {
        public Guid Id { get; set; }
        public string UserName { get; set; } //email
        public bool? Active { get; set; } = true;

        [DataType(DataType.Password)]
        [MinLength(4)]
        public string Password { get; set; } //senha
        public List<Role> Roles { get; set; }
        public Meta Meta { get; set; } //info user

    }


    public class Role
    {
        [JsonIgnore]
        public int Id { get; set; }

        public string Display { get; set; }
        public bool Primary { get; set; }
    }

    public class Meta
    {

        public string ResourceType { get; set; } = "User";
        public string Location { get; set; } = "/User/id";

        [DataType(DataType.DateTime)]
        public DateTime Created { get; set; } = DateTime.Now;

        [DataType(DataType.DateTime)]
        public DateTime LastModified { get; set; } = DateTime.Now;

    }


}
