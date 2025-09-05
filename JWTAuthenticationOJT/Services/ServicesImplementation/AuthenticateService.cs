using Azure.Core;
using JWTAuthenticationOJT.Auth;
using JWTAuthenticationOJT.ServicesInterfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthenticationOJT.Services.Implementation
{
    public class AuthenticateService : IAuthenticateService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticateService(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<object> LoginAsync(LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                if (!user.IsEmailConfirmed)
                    return new { Error = "Email not verified." };

                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = CreateClaims(user.UserName, userRoles);

                var token = CreateToken(authClaims);
                var refreshToken = GenerateRefreshToken();

                int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshDays);
                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshDays);

                await _userManager.UpdateAsync(user);

                return new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken = refreshToken,
                    Expiration = token.ValidTo,
                    Roles = userRoles
                };
            }
            return null;
        }

        public async Task<object> RegisterAsync(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null) return new { Error = "User already exists!" };

            var user = new ApplicationUser
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                BiometricType = model.BiometricType,
                UseFingerprint = model.BiometricType == "Fingerprint",
                UseFaceId = model.BiometricType == "FaceID"
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded) return new { Error = "User creation failed!" };

            var verificationCode = new Random().Next(1000, 9999).ToString();
            user.EmailVerificationCode = verificationCode;
            user.IsEmailConfirmed = false;
            user.FcmToken = Guid.NewGuid().ToString("N");

            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            await _userManager.AddToRoleAsync(user, UserRoles.User);

            await SendEmailAsync(user.Email, "Email Verification Code", verificationCode);

            return new { Status = "Success", Message = "User created. Check email for verification code." };
        }

        public async Task<object> BiometricLoginAsync(BiometricLoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null) return new { Error = "Invalid user" };

            if ((model.BiometricType == "Fingerprint" && user.UseFingerprint) ||
                (model.BiometricType == "FaceID" && user.UseFaceId))
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = CreateClaims(user.UserName, userRoles);
                var token = CreateToken(authClaims);

                return new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    Expiration = token.ValidTo,
                    Roles = userRoles
                };
            }

            return new { Error = "Biometric type not matched" };
        }

        public async Task<object> RegisterAdminAsync(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null) return new { Error = "User already exists!" };

            var user = new ApplicationUser
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                IsEmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded) return new { Error = "User creation failed!" };

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));

            await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            return new { Status = "Success", Message = "Admin created successfully!" };
        }

        public async Task<string> VerifyEmailAsync(EmailVerificationModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null) return "User not found";
            if (user.IsEmailConfirmed) return "Email already verified";

            if (user.EmailVerificationCode == model.Code)
            {
                user.IsEmailConfirmed = true;
                user.EmailVerificationCode = null;
                await _userManager.UpdateAsync(user);
                return "Email verified successfully.";
            }
            return "Invalid verification code.";
        }

        public async Task<string> RequestPasswordResetAsync(PasswordResetRequestModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return "User not found";

            var resetCode = new Random().Next(1000, 9999).ToString();
            user.PasswordResetCode = resetCode;
            user.PasswordResetCodeExpiry = DateTime.UtcNow.AddMinutes(10);
            await _userManager.UpdateAsync(user);

            await SendEmailAsync(user.Email, "Password Reset Code", resetCode);
            return "Password reset code sent.";
        }

        public async Task<string> ResetPasswordAsync(PasswordResetModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return "User not found";

            if (user.PasswordResetCode != model.Code || user.PasswordResetCodeExpiry < DateTime.UtcNow)
                return "Invalid or expired reset code.";

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);
            if (!result.Succeeded) return "Password reset failed.";

            user.PasswordResetCode = null;
            user.PasswordResetCodeExpiry = null;
            await _userManager.UpdateAsync(user);
            return "Password has been reset.";
        }

        public async Task<object> RefreshTokenAsync(TokenModel tokenModel)
        {
            var principal = GetPrincipalFromExpiredToken(tokenModel.AccessToken);
            if (principal == null) return new { Error = "Invalid token" };

            var username = principal.Identity.Name;
            var user = await _userManager.FindByNameAsync(username);
            if (user == null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return new { Error = "Invalid refresh token" };

            var newAccessToken = CreateToken(principal.Claims.ToList());
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            return new
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                RefreshToken = newRefreshToken
            };
        }

        public async Task<bool> RevokeAsync(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) return false;

            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);
            return true;
        }

        public async Task<bool> RevokeAllAsync()
        {
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await _userManager.UpdateAsync(user);
            }
            return true;
        }

        public async Task<bool> SaveFcmTokenAsync(string username, SaveFcmTokenModel model)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) return false;

            user.FcmToken = model.FcmToken;
            await _userManager.UpdateAsync(user);
            return true;
        }

        public async Task<object> GetFcmTokenAsync(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) return null;

            return new { FcmToken = user.FcmToken };
        }

        public async Task<object> AssignRoleAsync(AssignRoleModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null) return new { Error = "User not found." };
            if (!await _roleManager.RoleExistsAsync(model.Role)) return new { Error = "Invalid role." };

            var currentRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user, currentRoles);
            await _userManager.AddToRoleAsync(user, model.Role);

            return new { Status = "Success", Message = $"Role '{model.Role}' assigned to '{model.Username}'." };
        }

        public async Task<object> GetAllUserRolesAsync()
        {
            var users = _userManager.Users.ToList();
            var result = new List<object>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                result.Add(new { Username = user.UserName, Roles = roles, user.BiometricType});
            }
            return result;
        }


        #region Helper Methods
        private List<Claim> CreateClaims(string username, IList<string> roles)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            return claims;
        }

        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int minutes);

            return new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(minutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        private async Task SendEmailAsync(string toEmail, string subject, string code)
        {
            var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential("nextgenmobileflutter@gmail.com", "yhxu umnd tauy gfuq"),
                EnableSsl = true
            };

            string messageBody = $@"
             <html>
             <body style='font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;'>
               <div style='max-width: 500px; margin: auto; background-color: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>
                  <div style='text-align: center;'>
                    <img src='https://i.postimg.cc/h4MXLWqF/logo.png' alt='NextGen Logo' style='max-width: 120px; margin-bottom: 20px;' />
                    <h2 style='color: #333;'>WELCOME TO FLUTTER NEXTGEN</h2>
                    <p style='color: #555;'>Hello,</p>
                    <p style='color: #555;'>Your verification code for NextGen is:</p>
                    <div style='font-size: 28px; font-weight: bold; letter-spacing: 4px; color: white; background-color: #4CAF50; padding: 10px 20px; border-radius: 6px; display: inline-block; margin: 15px 0;'>
                    {code}
                  </div>
                   <p style='color: #555;'>Please enter this code to continue.</p>
                   <p style='color: #777; font-size: 12px;'>If you didn’t request this, you can safely ignore this email.</p>
                  </div>
                </div>
             </body>
             </html>";

            var mailMessage = new MailMessage
            {
                From = new MailAddress("nextgenmobileflutter@gmail.com", "NextGen Flutter"),
                Subject = subject,
                Body = messageBody,
                IsBodyHtml = true,
            };

            mailMessage.To.Add(toEmail);
            await smtpClient.SendMailAsync(mailMessage);
        }
        #endregion
    }
}
