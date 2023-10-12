using Identity.Constant;
using Identity.Models;
using Identity.Models.Login;
using Identity.Models.Signup;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Services.Models;
using Services.Services.Email;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Identity.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IEmailService _emailService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(IEmailService emailService, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _emailService = emailService;
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            //Check User Exist 
            var userExist = await _userManager.FindByEmailAsync(registerUser.EmailAddress);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new Response
                {
                    Status = ResponseConst.Error,
                    Message = SignupConst.UserExists
                });
            }

            //Add the User in the database
            IdentityUser user = new()
            {
                Email = registerUser.EmailAddress,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
            };
            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response
                    {
                        Status = ResponseConst.Error,
                        Message = SignupConst.CreatedFailure
                    });
                }
                //Add role to the user....

                await _userManager.AddToRoleAsync(user, role);

                //Add Token to Verify the email....
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK, new Response 
                { 
                    Status = ResponseConst.Success, 
                    Message = $"User created & Email Sent to {user.Email} SuccessFully" 
                });

            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = ResponseConst.Error,
                    Message = SignupConst.RoleExists
                });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var message = new Message(new string[] { user.Email! }, "OTP Confrimation", token);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                 new Response { Status = ResponseConst.Success, Message = $"We have sent an OTP to your Email {user.Email}" });
            }
            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }


                var jwtToken = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                });
                //returning the token...

            }
            return Unauthorized();
        }

        [HttpPost("login-2fa")]
        public async Task<IActionResult> LoginWithOTPCode(string otp, string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", otp, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var jwtToken = GetToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });
                    //returning the token...

                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(2),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new Response
                    {
                        Status = ResponseConst.Success,
                        Message = EmailConst.EmailVerify
                    });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response
            {
                Status = ResponseConst.Error,
                Message = EmailConst.UserDoesnotExist
            });
        }

        [HttpGet("testmail")]
        public async Task<IActionResult> TestMailAsync(string email, string subject, string content)
        {
            var message = new Message(new string[]
            {
                email
            }, subject, content);

            _emailService.SendEmail(message);

            return StatusCode(StatusCodes.Status200OK, 
                new Response { Status = "Success", Message = "Email sent"});
        }

    }
}
