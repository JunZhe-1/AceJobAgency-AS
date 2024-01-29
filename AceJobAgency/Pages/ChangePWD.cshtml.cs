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
    public class ChangePWDModel : PageModel
    {

        private UserManager<IdentityUser> userManager { get; }
        private SignInManager<IdentityUser> signInManager { get; }
        //private  DbSet<Register> Registers { get; set; }

        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly IHttpContextAccessor _context;

        private readonly ILogger<ChangePWDModel> _logger;

        private readonly AuthDbContext _dbcontext; // Add this field


        //[BindProperty]
        //public Register RModel { get; set; }
        [BindProperty]
        public ChangePWD CModel { get; set; }


        [BindProperty]
        public string RecaptchaResponse { get; set; }

        //private string userEmail = "";


        public ChangePWDModel(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IDataProtectionProvider dataProtectionProvider,
         IHttpContextAccessor dbContext,
         ILogger<ChangePWDModel> logger,
         AuthDbContext _dbcontext)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.dataProtectionProvider = dataProtectionProvider;
            this._context = dbContext;
            this._logger = logger;
            this._dbcontext = _dbcontext;
        }



        public IActionResult OnGet()
        {
            if (_context.HttpContext.Session.GetString("SessionId") == null)
            {
                _logger.LogInformation("Cannot found any session ID in your session ");
                return RedirectToPage("Login");

            }


            var sessionTimeoutSeconds = _context.HttpContext.Session.GetInt32("UserSessionTimeout");
            _logger.LogInformation($"time: {sessionTimeoutSeconds}");

            var currentTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            var lastActivityTime = _context.HttpContext.Session.GetInt32("LastActivityTime") ?? currentTime;

            if (sessionTimeoutSeconds.HasValue && (currentTime - lastActivityTime) > sessionTimeoutSeconds)
            {

                _context.HttpContext.Session.Clear();

                foreach (var key in _context.HttpContext.Session.Keys)
                {
                    _context.HttpContext.Session.Remove(key);
                }
                _logger.LogInformation($"Your Session is already time out");

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



            if (CModel.Password != null && CModel.ConfirmPassword != null)
            {
                if (CModel.Password != null)
                {
                    if (!IsStrongPassword(CModel.Password))
                    {
                        ModelState.AddModelError(nameof(CModel.Password), "Password must be at least 12 characters long and include a combination of lower-case, upper-case, numbers, and special characters.");
                        return Page();
                    }
                }


                try
                {
                    var password_protector = dataProtectionProvider.CreateProtector("Password");
                    var ProtectPassword = password_protector.Protect(CModel.Password);

                    var userEmail = DecryptEmail(_context.HttpContext.Session.GetString("User_Email"));
                    var login_usr = await userManager.FindByEmailAsync(userEmail);
                    _logger.LogInformation($"User {userEmail} is found");
                    // update password
                    var changePasswordResult = await userManager.ChangePasswordAsync(login_usr, CModel.Current_Password, CModel.Password);

                    if (changePasswordResult.Succeeded)
                    {
                        _logger.LogInformation($"Enter statement");

                        if (string.IsNullOrEmpty(userEmail))
                        {
                            _logger.LogInformation($"User email is null or empty. Password update unsuccessful.");
                            return RedirectToPage("/Error");
                        }
                        var allUsers = _dbcontext.Registers.ToList(); // Fetch all users from the database
                        var user = allUsers.FirstOrDefault(u => DecryptEmail(u.Email) == userEmail);


                        if (user == null)
                        {
                            _logger.LogInformation($"{userEmail} password update unsecessfully");
                            return NotFound();  

                        }


                        _logger.LogInformation($"{userEmail} password update seccesfully");
                        user.Password = ProtectPassword;
                        user.ConfirmPassword = ProtectPassword;

                        await _dbcontext.SaveChangesAsync();

                        return RedirectToPage("/user_detail4");
                    }
                    else if (!changePasswordResult.Succeeded)
                    {
                        ModelState.AddModelError(nameof(CModel.Current_Password), "Your Current Password is Wrong");
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
                    _logger.LogInformation($"error in 208 lines");
                    return NotFound();

                }






            }
            return Page();
        }

        private string DecryptEmail(string encryptedEmail)
        {
            // Use the appropriate decryption logic here
            var protector = dataProtectionProvider.CreateProtector("EmailProtection");
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
