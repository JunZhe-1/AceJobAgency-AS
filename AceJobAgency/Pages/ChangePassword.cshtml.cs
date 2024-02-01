using AceJobAgency.viewModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using WebApplication3.Model;
using WebApplication3.ViewModels;

namespace AceJobAgency.Pages
{
    public class ChangePasswordModel : PageModel
    {

        private UserManager<IdentityUser> userManager { get; }
        private SignInManager<IdentityUser> signInManager { get; }
        //private  DbSet<Register> Registers { get; set; }

        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly IHttpContextAccessor _context;

        private readonly ILogger<ChangePasswordModel> _logger;

        private readonly AuthDbContext _dbcontext; // Add this field


        //[BindProperty]
        //public Register RegisteringModel { get; set; }
        [BindProperty]
        public ChangePassword ChangePwdModel { get; set; }


        [BindProperty]
        public string RecaptchaResponse { get; set; }

        //private string userEmail = "";


        public ChangePasswordModel(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IDataProtectionProvider dataProtectionProvider,
         IHttpContextAccessor dbContext,
         ILogger<ChangePasswordModel> logger,
         AuthDbContext _dbcontext)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.dataProtectionProvider = dataProtectionProvider;
            this._context = dbContext;
            this._logger = logger;
            this._dbcontext = _dbcontext;
        }



        public async Task<IActionResult> OnGet()
        {
            if (_context.HttpContext.Session.GetString("SessionId") == null)
            {
                _logger.LogInformation("Your session has no session id ");
                return RedirectToPage("Login");

            }


            var sessionTimeoutSeconds = _context.HttpContext.Session.GetInt32("UserSessionTimeout");
            _logger.LogInformation($"Time remainning: {sessionTimeoutSeconds}");

            var currentTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            var lastActivityTime = _context.HttpContext.Session.GetInt32("LastActivityTime") ?? currentTime;

            if (sessionTimeoutSeconds.HasValue && (currentTime - lastActivityTime) > sessionTimeoutSeconds)
            {

                _context.HttpContext.Session.Clear();

                foreach (var key in _context.HttpContext.Session.Keys)
                {
                    _context.HttpContext.Session.Remove(key);
                }
                _logger.LogInformation($"Your session is expired");
                await signInManager.SignOutAsync();
                return RedirectToPage("Login");
            }
            else
            {
                _context.HttpContext.Session.SetInt32("LastActivityTime", (int)currentTime);

                // Continue processing for an active session
                // _context.HttpContext.Session.SetInt32("StudentId", 50);
            }

            return Page();
        }


        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {

            // Inside your OnPostAsync method
            var recaptcha_SecretKey = "6LdMGV8pAAAAAL3gcsIM5YrOFq4ERQvJKpcCpAoJ";
            var recaptcha_Api_Url = "https://www.google.com/recaptcha/api/siteverify";

            var recaptcha__Client = new HttpClient();
            var recaptchaResult = await recaptcha__Client.PostAsync(recaptcha_Api_Url, new FormUrlEncodedContent(new List<KeyValuePair<string, string>>
                {
                new KeyValuePair<string, string>("secret", recaptcha_SecretKey),
                new KeyValuePair<string, string>("response", RecaptchaResponse),
                new KeyValuePair<string, string>("remoteip", HttpContext.Connection.RemoteIpAddress.ToString())
            }));


            if (!recaptchaResult.IsSuccessStatusCode)
            {
                ModelState.AddModelError("", "Failed to validate reCAPTCHA.");
                return Page();
            }

            var recaptcha_Content = await recaptchaResult.Content.ReadAsStringAsync();
            var recaptcha_Response = JsonConvert.DeserializeObject<RecaptchaResponse>(recaptcha_Content);

            if (!recaptcha_Response.Success)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed.");
                return Page();
            }



            if (ChangePwdModel.Password != null && ChangePwdModel.ConfirmPassword != null)
            {
                if (ChangePwdModel.Password != null)
                {
                    if (!IsStrongPassword(ChangePwdModel.Password))
                    {
                        ModelState.AddModelError(nameof(ChangePwdModel.Password), "Password must be at least 12 characters long and include a combination of lower-case, upper-case, numbers, and special characters.");
                        return Page();
                    }
                }


                try
                {
                    var password_protector = dataProtectionProvider.CreateProtector("PasswordProtector");
                    var ProtectPassword = password_protector.Protect(ChangePwdModel.Password);

                    var userEmail = DecryptEmail(_context.HttpContext.Session.GetString("User_Email"));
                    var login_usr = await userManager.FindByEmailAsync(userEmail);
                    _logger.LogInformation($"User {userEmail} is correct");
                    // update password
                    var changePasswordResult = await userManager.ChangePasswordAsync(login_usr, ChangePwdModel.PasswordNow, ChangePwdModel.Password);

                    if (changePasswordResult.Succeeded)
                    {
                        _logger.LogInformation($"");

                        if (string.IsNullOrEmpty(userEmail))
                        {
                            _logger.LogInformation($" Password update failed due to incorrect or not exist email address");
                            return RedirectToPage("/Error");
                        }
                        var allUsers = _dbcontext.Registers.ToList(); // Fetch all users from the database
                        var user = allUsers.FirstOrDefault(u => DecryptEmail(u.Email) == userEmail);


                        if (user == null)
                        {
                            _logger.LogInformation($"{userEmail} Password update failed");
                            return NotFound();  

                        }


                        _logger.LogInformation($"{userEmail} Password update seccesfully");
                        user.Password = ProtectPassword;
                        user.ConfirmPassword = ProtectPassword;

                        await _dbcontext.SaveChangesAsync();

                        return RedirectToPage("/UserDetail");
                    }
                    else if (!changePasswordResult.Succeeded)
                    {
                        ModelState.AddModelError(nameof(ChangePwdModel.PasswordNow), "Your Current Password is incorrect");
                        return Page();
                    }
                    else
                    {
                        if (!changePasswordResult.Succeeded)
                        {
                            foreach (var error in changePasswordResult.Errors)
                            {
                                ModelState.AddModelError(string.Empty, error.Description);
                            }

                            return Page();
                        }

                    }
                }
                catch (Exception ex)
                {
                    _logger.LogInformation($"error dont know how many");
                    return NotFound();

                }






            }
            return Page();
        }

        private string DecryptEmail(string encryptedEmail)
        {
            // Use the appropriate decryption logic here
            var protector = dataProtectionProvider.CreateProtector("EmailAdressProtector");
            return protector.Unprotect(encryptedEmail);
        }

        private bool IsStrongPassword(string password)
        {

            return password.Length >= 12
                && password.Any(char.IsUpper)
                && password.Any(char.IsLower)
                && password.Any(char.IsDigit)
                && password.Any(ch => !char.IsLetterOrDigit(ch));
        }
    }
}
