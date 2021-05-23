using System.ComponentModel.DataAnnotations;

namespace ScimVersed.Models
{
    public class Authenticate
    {

        public string username { get; set; }
        [Required]
        public string grant_type { get; set; }
        public string password { get; set; }
        public string refresh_token { get; set; }

        public string client_secret { get; set; }
        //O client_secret é um segredo conhecido apenas pelo aplicativo e pelo servidor de autorização,
        //e normalmente é usado para fazer login sem username e password 

    }

}