using System.ComponentModel.DataAnnotations;

namespace Identity.Models.Signup
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "Username is required!")]
        public string Username { get; set; } = string.Empty;

        [EmailAddress(ErrorMessage = "Incorrect email format!")]
        [Required(ErrorMessage = "Email is required!")]
        public string EmailAddress { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required!")]
        public string Password { get; set; } = string.Empty;
    }
}
