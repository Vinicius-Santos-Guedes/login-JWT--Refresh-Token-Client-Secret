using Microsoft.AspNetCore.Mvc;
using AuthJwt.Models;
using AuthJwt.Models.Return;
using AuthJwt.Services;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using ScimVersed.Models;
using AuthJwt.Repositories;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using RSALib;
using System;

namespace AuthJwt.Controllers
{
    [Route("v1/account")]
    public class LoginController : ControllerBase
    {

        private static IWebHostEnvironment _hostEnvironment;


        private readonly IConfiguration _configuration;


        public LoginController(IConfiguration configuration, IWebHostEnvironment environment)
        {
            _hostEnvironment = environment;
            _configuration = configuration;
        }


        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public ActionResult Authenticate([FromForm] Authenticate authenticate)
        {

            #region Autenticação com username e password
            if (authenticate.grant_type.Equals("password"))
            {

                //pega o usuário que tem o username e a senha equivalentes
                var user = UserRepository.users.Where(x => x.Password == authenticate.password && x.UserName == authenticate.username).FirstOrDefault();

                //caso não encontrar retorna status code erro 404(não encontrado)
                if (user == null)
                {
                    return NotFound();
                }

                //gera o token access
                var access_token = TokenService.GenerateToken(user);
                //gera o refresh token
                var refreshToken = TokenService.GenerateRefreshToken(user);

                //refresh token com Cookie
                //ele vai guardar o refresh token nos cookie
                //evitando o possível roubo desse refresh token via javascript com a propriedade HttpOnly
                #region use cookie
                Response.Cookies.Append(
                    "RefreshToken",
                    refreshToken,
                    new Microsoft.AspNetCore.Http.CookieOptions()
                    {
                        //expiração com o valor predefinido
                        Expires = DateTimeOffset.Now.AddMinutes(30),
                        HttpOnly = true,//adicionado quando não queremos que o client veja o token via javascript
                        Path = "/"
                    }
                );
                #endregion use cookie

                //gera o token
                var token = new Token
                {
                    token_type = "Bearer",
                    scope = "https://localhost:5001/readwrite.all",
                    RefreshToken = refreshToken,
                    expires_in = Settings.Expires_in.Minutes,
                    ext_expires_in = Settings.Expires_in.Minutes,
                    access_token = access_token,
                };


                return Ok(token);
            }
            #endregion Autenticação com username e password

            #region RefreshToken
            else if (authenticate.grant_type.Equals("refresh_token"))
            {
                User user = new User();
                //caso o refresh token esteja mapeado para enviar pelo cookie, atribui ela na variável 
                if (string.IsNullOrEmpty(authenticate.refresh_token) && Request.Cookies["RefreshToken"] != null)
                    authenticate.refresh_token = Request.Cookies["RefreshToken"];

                //pega o usuário e suas permissões antigas
                user = TokenService.GetUserbyValidRefreshToken(authenticate.refresh_token);

                //gera o token access
                var access_token = TokenService.GenerateToken(user);
                //gera o refresh token
                var refreshToken = TokenService.GenerateRefreshToken(user);

                //gera o token
                return Ok(new Token
                {
                    access_token = access_token,
                    scope = "https://localhost:5001/readwrite.all",
                    expires_in = Settings.Expires_in.Minutes,
                    ext_expires_in = 3600,//2hoosra para expirar
                    token_type = "bearer",
                    RefreshToken = refreshToken,
                });

            }
            #endregion RefreshToken

            #region Autenticação com Client Secret, 

            else if (authenticate.grant_type.Equals("client_credentials"))
            {

                //verifica o client secret é valido
                bool validPfx = RSAPFX.DecryptUsingCertificate(authenticate.client_secret, _configuration["RSA_PRIVATEKEY_PATHPFX"], _configuration["ValidKeys"]);

                //verifica o client secret é valido
                RSAHandler rsa = new RSAHandler();
                bool validPEM = rsa.IsRSAToken(authenticate.client_secret, _configuration["RSA_PRIVATEKEY_PATHPEM"], _configuration["ValidKeys"].Split('-'));

                //verifica o client secret é valido
                if (validPfx || validPEM)
                {
                    //se for valido cria um user com acesso total para
                    User user = new User()
                    {
                        UserName = "AuthJwt",
                        Roles = new List<Role>() { new Role() { Display = "FullAcess" } }
                    };
                    //gera o token access
                    var access_token = TokenService.GenerateToken(user);
                    //gera o refresh token
                    var refreshToken = TokenService.GenerateRefreshToken(user);

                    #region use cookie

                    Response.Cookies.Append(
                        "RefreshToken",
                        refreshToken,
                        new Microsoft.AspNetCore.Http.CookieOptions()
                        {
                            //expiração com o valor predefinido
                            Expires = DateTimeOffset.Now.AddMinutes(30),
                            HttpOnly = true,//adicionado quando não queremos que o client veja o token via javascript
                            Path = "/"
                        }
                    );
                    #endregion use cookie

                    //gera o token
                    return Ok(new Token
                    {
                        access_token = access_token,
                        //scope = "https://localhost:5001/readwrite.all",
                        expires_in = Settings.Expires_in.Minutes,
                        ext_expires_in = 3600,//2hoosra para expirar
                        token_type = "bearer",
                        RefreshToken = refreshToken,
                    });
                }
                return Unauthorized();
            }
            #endregion Autenticação com Client Secret
            #region Grant type não encontrado

            else
            {
                return NotFound(authenticate.grant_type + " error: GrantType is not supported");

            }
            #endregion Grant type não encontrado

        }


        [HttpPost]
        [Route("logout")]
        [AllowAnonymous]
        public ActionResult Logout()
        {

            Response.Cookies.Delete("RefreshToken");
            return Ok();
        }

    }


}