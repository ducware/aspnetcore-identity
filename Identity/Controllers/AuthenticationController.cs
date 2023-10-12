using Identity.Constant;
using Identity.Models;
using Identity.Models.Signup;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Services.Models;
using Services.Services.Email;

namespace Identity.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IEmailService _emailService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(IEmailService emailService, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _emailService = emailService;
            _userManager = userManager;
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
        public async Task<IActionResult> TestMailAsync()
        {
            var message = new Message(new string[]
            {
                "nguyentrandau2018@gmail.com"
            }, "test", "<h1>Test</h1>");

            _emailService.SendEmail(message);

            return StatusCode(StatusCodes.Status200OK, 
                new Response { Status = "Success", Message = "Email sent"});
        }

    }
}
