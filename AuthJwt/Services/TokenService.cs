using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using AuthJwt.Models;
using System.Threading.Tasks;
using ScimVersed.Models;
using System.Security.Principal;

namespace AuthJwt.Services
{
    public class TokenService
    {
        public static string GenerateToken(User user)
        {

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Settings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                new Claim(ClaimTypes.Name, user.UserName.ToString()),
                new Claim("sub", user.UserName.ToString()),

                }),
                Expires = DateTime.UtcNow.AddSeconds(Settings.Expires_in.TotalSeconds),//em quanto segundos o token vai expirar
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };
            foreach (Role role in user.Roles)//adciona todas as permissões do usuáris
                tokenDescriptor.Subject.AddClaim(new Claim(ClaimTypes.Role, role.Display));
            
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static string GenerateRefreshToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Settings.Secret_Refresh);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //dentro das Claim será guardado o username e as roles
                Subject = new ClaimsIdentity(new Claim[]
                {
                new Claim("sub", user.UserName),
                new Claim("iss", "http://localhost:5001")
                }),
                Expires = DateTime.UtcNow.AddDays(7),//expira em 7dias ou seja 604800s
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            foreach (Role role in user.Roles)//adciona todas as permissões do usuáris
                tokenDescriptor.Subject.AddClaim(new Claim(ClaimTypes.Role, role.Display));

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


        public static User GetUserbyValidRefreshToken(string jwt)
        {
            var token = jwt.Replace("Bearer ", string.Empty);

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Settings.Secret_Refresh);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;

                var username = (jwtToken.Claims.FirstOrDefault(x => x.Type == "sub").Value);
                List<Role> roles = jwtToken.Claims.Where(x => x.Type == "role")
                    .Select(x => new Role() { Display = x.Value })
                    .ToList();


                User user = new User
                {
                    UserName = username,
                    Roles = roles,
                };


                // return account id from JWT token if validation successful
                return user;
            }
            catch (Exception e)
            {
                // return null if validation fails
                throw e;

            }
        }

        public static bool ValidateToken(string authToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters();

            SecurityToken validatedToken;
            IPrincipal principal = tokenHandler.ValidateToken(authToken, validationParameters, out validatedToken);
            return true;
        }

        private static TokenValidationParameters GetValidationParameters()
        {
            var key = Encoding.ASCII.GetBytes(Settings.Secret_Refresh);

            return new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,

                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = true, //Obtém ou define um booleano para controlar se o tempo de vida será validado durante a validação do token.
                ValidateAudience = false, //Obtém ou define um booleano para controlar se o público será validado durante a validação do token.
                ValidateIssuer = false,   //Obtém ou define um booleano para controlar se o emissor será validado durante a validação do token.
            };
        }
    }
}
