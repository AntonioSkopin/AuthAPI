using AuthAPI.Auth.Entities;
using AuthAPI.Auth.Models;
using AuthAPI.Auth.Services;
using AuthAPI.Helpers;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthAPI.Auth.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IAuthService _authService;
        private IMapper _mapper;

        public AuthController
        (
            IAuthService authService,
            IMapper mapper
        )
        {
            _authService = authService;
            _mapper = mapper;
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
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim(ClaimTypes.Name, user.Gd.ToString())
                    }),
                    Expires = DateTime.UtcNow.AddDays(7)
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

        [HttpDelete]
        public async Task<IActionResult> DeleteUser(int id)
        {
            await _authService.Delete(id);
            return Ok();
        }

        [HttpGet]
        public async Task<ActionResult<User>> GetByGd(Guid gd)
        {
            var user = await _authService.GetByGd(gd);
            var model = _mapper.Map<UserModel>(user);
            return Ok(model);
        }
    }
}
