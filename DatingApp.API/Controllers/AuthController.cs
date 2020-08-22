using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.DTO;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;

        }
        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            //validate request

            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();

            if (await _repo.UserExists(userForRegisterDto.Username))
            {
                return BadRequest("Username already exists");
            }

            var userToCreate = new User
            {
                Username = userForRegisterDto.Username
            };

            var createdUser = await _repo.Register(userToCreate, userForRegisterDto.Username);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var userFromRepo = await _repo.Login(userForLoginDto.Username.ToLower(), userForLoginDto.Password); //check if user is valid

            if (userFromRepo == null)
            {
                return Unauthorized();
            }

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userForLoginDto.Username)
            };  //building up a token using user id and user name

            //we create a security key, so we can use it to validate
            var key = new SymmetricSecurityKey(Encoding.UTF8.
            GetBytes(_config.GetSection("AppSettings:Token").Value));

            //we use the key to sign and also encrypt the key
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            //we create the token, we pass our claim as the subject, set an expiry date and use our encrypted key
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1), //expires in a days time
                SigningCredentials = creds
            };

            //token handler
            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);
            
            //write tokem in the response
            return Ok(new {
                token = tokenHandler.WriteToken(token)
            });
        }
    }
}