using JWTAuthenticationOJT.Auth;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JWTAuthenticationOJT.ServicesInterfaces
{
    public interface IAuthenticateService
    {
        Task<object> LoginAsync(LoginModel model);
        Task<object> BiometricLoginAsync(BiometricLoginModel model);
        Task<object> RegisterAsync(RegisterModel model);
        Task<object> RegisterAdminAsync(RegisterModel model);
        Task<string> VerifyEmailAsync(EmailVerificationModel model);
        Task<string> RequestPasswordResetAsync(PasswordResetRequestModel model);
        Task<string> ResetPasswordAsync(PasswordResetModel model);
        Task<object> RefreshTokenAsync(TokenModel tokenModel);
        Task<bool> RevokeAsync(string username);
        Task<bool> RevokeAllAsync();
        Task<bool> SaveFcmTokenAsync(string username, SaveFcmTokenModel model);
        Task<object> GetFcmTokenAsync(string username);
        Task<object> AssignRoleAsync(AssignRoleModel model);
        Task<object> GetAllUserRolesAsync();

    }
}
