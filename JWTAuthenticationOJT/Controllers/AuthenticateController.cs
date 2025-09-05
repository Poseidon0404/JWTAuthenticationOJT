using JWTAuthenticationOJT.Auth;
using JWTAuthenticationOJT.ServicesInterfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace JWTAuthenticationOJT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly IAuthenticateService _authService;

        public AuthenticateController(IAuthenticateService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel model) =>
            Ok(await _authService.LoginAsync(model));

        [HttpPost("Biometriclogin")]
        public async Task<IActionResult> Biometriclogin(BiometricLoginModel model) =>
            Ok(await _authService.BiometricLoginAsync(model));

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel model) =>
            Ok(await _authService.RegisterAsync(model));

        [HttpPost("register-admin")]
        public async Task<IActionResult> RegisterAdmin(RegisterModel model) =>
            Ok(await _authService.RegisterAdminAsync(model));

        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail(EmailVerificationModel model) =>
            Ok(await _authService.VerifyEmailAsync(model));

        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset(PasswordResetRequestModel model) =>
            Ok(await _authService.RequestPasswordResetAsync(model));

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(PasswordResetModel model) =>
            Ok(await _authService.ResetPasswordAsync(model));

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel) =>
            Ok(await _authService.RefreshTokenAsync(tokenModel));

        [Authorize]
        [HttpPost("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username) =>
            Ok(await _authService.RevokeAsync(username));

        [Authorize]
        [HttpPost("revoke-all")]
        public async Task<IActionResult> RevokeAll() =>
            Ok(await _authService.RevokeAllAsync());

        [Authorize]
        [HttpPost("save-fcm-token")]
        public async Task<IActionResult> SaveFcmToken(SaveFcmTokenModel model) =>
            Ok(await _authService.SaveFcmTokenAsync(User.Identity.Name, model));

        [HttpGet("get-fcm-token/{username}")]
        public async Task<IActionResult> GetFcmToken(string username) =>
            Ok(await _authService.GetFcmTokenAsync(username));

        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole(AssignRoleModel model) =>
            Ok(await _authService.AssignRoleAsync(model));

        [HttpGet("all-user-roles")]
        public async Task<IActionResult> GetAllUserRoles() =>
            Ok(await _authService.GetAllUserRolesAsync());
    }
}
