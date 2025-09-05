using Microsoft.AspNetCore.Identity;

namespace JWTAuthenticationOJT.Auth
{
    public class ApplicationUser : IdentityUser
    {
        public bool UseFingerprint { get; set; } = false;
        public bool UseFaceId { get; set; } = false;
        public string? BiometricType { get; set; }

        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }

        public string? EmailVerificationCode { get; set; }
        public bool IsEmailConfirmed { get; set; } = false;

        public string? PasswordResetCode { get; set; }
        public DateTime? PasswordResetCodeExpiry { get; set; }

        public string? FcmToken { get; set; }


    }
}
