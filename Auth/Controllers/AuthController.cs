using AuthAPI.Auth.Entities;
using AuthAPI.Auth.Models;
using AuthAPI.Auth.Services;
using AuthAPI.Helpers;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthAPI.Auth.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IAuthService _authService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;

        public AuthController
        (
            IAuthService authService,
            IMapper mapper,
            IOptions<AppSettings> appSettings
        )
        {
            _authService = authService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Authenticate([FromBody] AuthenticateModel model)
        {
            var user = _authService.Authenticate(model.Username, model.Password);

            if (user == null)
                return Unauthorized(new { message = "Username or password is incorrect" });

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim(ClaimTypes.Name, user.Gd.ToString())
                    }),
                    Expires = DateTime.UtcNow.AddDays(7),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                // return basic user info and authentication token
                return Ok(new
                {
                    Gd = user.Gd,
                    Username = user.Username,
                    Firstname = user.Firstname,
                    Lastname = user.Lastname,
                    Token = tokenString
                });
            }
            catch (AppException ex)
            {
                // Return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<ActionResult<User>> Register([FromBody] RegisterModel model)
        {
            // Map model to entity
            var user = _mapper.Map<User>(model);

            try
            {
                // Create user
                await _authService.Register(user, model.Password);
                return Ok();
            }
            catch (AppException ex)
            {
                // Return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize]
        [HttpPut]
        public async Task<IActionResult> UpdateUser(Guid gd, [FromBody] UpdateModel model)
        {
            // Map model to entity and set id
            var user = _mapper.Map<User>(model);
            user.Gd = gd;

            try
            {
                // Update user 
                await _authService.Update(user, model.Password);
                return Ok();
            }
            catch (AppException ex)
            {
                // Return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize]
        [HttpDelete]
        public async Task<IActionResult> DeleteUser(int id)
        {
            await _authService.Delete(id);
            return Ok();
        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetByGd(Guid gd)
        {
            var user = await _authService.GetByGd(gd);
            var model = _mapper.Map<UserModel>(user);
            return Ok(model);
        }
    }
}
