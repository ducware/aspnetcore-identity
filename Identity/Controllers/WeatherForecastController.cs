using Identity.Constant;
using Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Net;

namespace Identity.Controllers
{
    [ApiController]
    [Route("test-role")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet("no-role")]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [Authorize]
        [HttpGet("all-role")]
        public async Task<IActionResult> AllRole()
        {
            return StatusCode(StatusCodes.Status200OK, new Response
            {
                Status = ResponseConst.Success,
                Message = "ALL ROLE AUTHORIZE"
            });
        }

        [Authorize(Roles = RoleConst.Admin)]
        [HttpGet("role-admin")]
        public async Task<IActionResult> RoleAdmin([FromHeader] string Authorization)
        {
            string authToken = Authorization.Substring("Bearer ".Length).Trim();
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken tokenS;
            try
            {
                tokenS = handler.ReadToken(authToken) as JwtSecurityToken;
                if (tokenS.ValidTo > DateTime.UtcNow)
                {
                    return StatusCode(StatusCodes.Status200OK, new Response
                    {
                        Status = ResponseConst.Success,
                        Message = "ROLE ADMIN AUTHORIZE"
                    });
                }
                else
                {
                    return Unauthorized(); // Token expired - return an Unauthorised status
                }
            }
            catch
            {
                // Token validation failed
                return Unauthorized();
            }
        }

        [Authorize(Roles = RoleConst.Customer)]
        [HttpGet("role-customer")]
        public async Task<IActionResult> RoleCustomer()
        {
            return StatusCode(StatusCodes.Status200OK, new Response
            {
                Status = ResponseConst.Success,
                Message = "ROLE CUSTOMER AUTHORIZE"
            });
        }

        [Authorize(Roles = RoleConst.User)]
        [HttpGet("role-user")]
        public async Task<IActionResult> RoleUser()
        {
            return StatusCode(StatusCodes.Status200OK, new Response
            {
                Status = ResponseConst.Success,
                Message = "ROLE USER AUTHORIZE"
            });
        }


    }
}