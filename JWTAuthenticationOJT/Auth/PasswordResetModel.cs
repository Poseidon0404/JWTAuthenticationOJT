namespace JWTAuthenticationOJT.Auth
{
    public class PasswordResetModel
    {
        public string Email { get; set; }
        public string Code { get; set; }
        public string NewPassword { get; set; }
    }
}
