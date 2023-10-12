using System.ComponentModel.DataAnnotations;

namespace Identity.Models.ResetPassword
{
    public class ResetPasswordModel
    {
        [Required]
        public string Password { get; set; } = null!;
        [Compare("Password", ErrorMessage = "The password and confirm password do match!")]
        public string ConfirmPassword { get; set;} = null!;
        public string Email { get; set; } = null!;
        public string Token { get; set; } = null!;
    }
}
