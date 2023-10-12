namespace Identity.Constant
{
    public class ResponseConst
    {
        public const string Error = "Error";
        public const string Success = "Success";
        
    }

    public class SignupConst
    {
        public const string CreatedFailure = "User created failure!";
        public const string CreatedSuccessfully = "User created successfully, check your email for active your account!";
        public const string UserExists = "User already exists!";
        public const string RoleExists = "This role doesnot exist!";

    }

    public class EmailConst
    {
        public const string EmailVerify = "Email verify successfully!";
        public const string UserDoesnotExist = "This user doesnot exist!";
        public const string CouldnotSendLink = "Couldnot send link to email, please try again!";
    }

    public class LoginConst
    {
        public const string InvalidCode = "Invalid code!";
        public const string UserDoesnotExist = "This user doesnot exist!";
    }

    public class ForgotPassConst
    {
        public const string PasswordChanged = "Password has been changed 👌";
        public const string PasswordResetFailed = "Password reset failure";
    }
}
