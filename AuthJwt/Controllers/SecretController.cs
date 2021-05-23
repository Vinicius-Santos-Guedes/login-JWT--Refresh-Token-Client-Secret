using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using RSALib;
using System;

namespace AuthJwt.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class SecretController : ControllerBase
    {
        private static IWebHostEnvironment _hostEnvironment;


        private readonly IConfiguration _configuration;


        public SecretController(IConfiguration configuration, IWebHostEnvironment environment)
        {
            _hostEnvironment = environment;
            _configuration = configuration;
        }

        /// <summary>
        /// se for um usuário com acesso manager ou tiver full access
        /// O client_secret é um segredo conhecido apenas pelo aplicativo e pelo servidor de autorização,
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Authorize(Roles = "manager,FullAccess")]
        public IActionResult Get()
        {

            //pega a chave do certificado, que será usada para gerar o client secret
            var data = _configuration["ValidKeys"];

            try
            {
                RSAHandler rsa = new RSAHandler();
                //gera o client secret com o certificado PEM
                string encryptdatpem = rsa.Encrypt(data, _configuration["RSA_PUBLICKEY_PATHPEM"]);
                return Ok(new { client_secret = encryptdatpem });
            }
            catch
            {
                //gera o client secret com o certificado PFX
                var encryptdatpfx = RSAPFX.EncryptUsingCertificate(data, _configuration["RSA_PUBLICKEY_PATHPFX"]);//vem nulo
                if (string.IsNullOrEmpty(encryptdatpfx)) throw new ArgumentException("RSA keys invalid");
                return Ok(new { client_secret = encryptdatpfx });
            }
        }


      

    }
}
