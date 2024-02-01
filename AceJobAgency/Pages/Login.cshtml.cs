using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using WebApplication3.Model;
using WebApplication3.Pages;
using WebApplication3.ViewModels;
using Newtonsoft.Json;

using AceJobAgency.viewModels;
using AceJobAgency.ViewModels;
using static System.Net.WebRequestMethods;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Collections.Generic;



namespace AceJobAgency.Pages
{
    public class LoginModel : PageModel
    {

        private UserManager<IdentityUser> userManager { get; }
        private SignInManager<IdentityUser> signInManager { get; }
        //private  DbSet<Register> Registers { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }


        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly AuthDbContext _dbcontext; // Add this field
        private readonly IHttpContextAccessor _context;

        private readonly ILogger<LoginModel> _logger;

        //[BindProperty]
        //public Register RegisteringModel { get; set; }
        [BindProperty]
        public Login LogModel { get; set; }


        [BindProperty]
        public string RecaptchaResponse { get; set; }





        public LoginModel(
          UserManager<IdentityUser> userManager,
          SignInManager<IdentityUser> signInManager,
          IDataProtectionProvider dataProtectionProvider,
           AuthDbContext dbContext,
           ILogger<LoginModel> logger,
           IHttpContextAccessor icontext)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.dataProtectionProvider = dataProtectionProvider;
            this._dbcontext = dbContext;
            this._logger = logger;
            this._context = icontext;
        }

        public void OnGet()
        {
            _logger.LogInformation("");
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
                    new KeyValuePair<string, string>("remoteip", _context.HttpContext.Connection.RemoteIpAddress.ToString())
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


            var RegexMail = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
            if (LogModel.Email != null)
            {
                if (!RegexMail.IsMatch(LogModel.Email) || LogModel.Email == null)
                {
                    ModelState.AddModelError(nameof(LogModel.Email), "Please enter a valid email address.");
                    return Page();
                }
            }
            else if (LogModel.Email == null)
            {
                ModelState.AddModelError("", "Please enter your ID and password");
                return Page();
            }



            var login_usr = await userManager.FindByEmailAsync(LogModel.Email);

            if (login_usr != null)
            {
                var allUsers = _dbcontext.Registers.ToList(); // Fetch all users from the database
                var user = allUsers.FirstOrDefault(u => DecryptEmail(u.Email) == login_usr.Email);
                var protector = dataProtectionProvider.CreateProtector("EmailAdressProtector");


                if (user != null)
                {
                    _context.HttpContext.Session.SetString("Who_Am_I", user.WhoAmI);
                    _context.HttpContext.Session.SetString("Date_Of_Birth", user.DateOfBirth.ToString());
                    _context.HttpContext.Session.SetString("First_Name", user.First_Name);
                    _context.HttpContext.Session.SetString("Last_Name", user.Last_Name);
                    _context.HttpContext.Session.SetString("NRIC", user.NRIC);

                }
                else
                {
                    _context.HttpContext.Session.SetString("Who_Am_I", "whoami");
                    _context.HttpContext.Session.SetString("Date_Of_Birth", "date");
                    _context.HttpContext.Session.SetString("First_Name", "fn");
                    _context.HttpContext.Session.SetString("Last_Name", "ln");
                    _context.HttpContext.Session.SetString("NRIC", "NRIC");

                }
                if (await userManager.IsLockedOutAsync(login_usr))
                {
                    var auditLog = new AuditLog
                    {
                        UserId = protector.Protect(login_usr.Email),
                        Timestamp = DateTime.UtcNow,
                        Action = "Account is locked but still trying"
                    };

                    _dbcontext.AuditLogs.Add(auditLog);
                    await _dbcontext.SaveChangesAsync();

                    ModelState.AddModelError("", "Your Account is locked out. Please try again later.");
                    return Page();
                }


                if (LogModel.Password != null)
                {
                    var hasher = new PasswordHasher<IdentityUser>();
                    var passworderificationResult = hasher.VerifyHashedPassword(login_usr, login_usr.PasswordHash, LogModel.Password);

                    if (passworderificationResult == PasswordVerificationResult.Success)
                    {
                        var email_protect = protector.Protect(login_usr.Email);

                        var session_timeout = 120; // 30 minutes
                        _context.HttpContext.Session.SetInt32("UserSessionTimeout", session_timeout);

                        //var session_id = _context.HttpContext.Session.GetString("User_Email");

                        //if (session_id != null && string.Equals(DecryptEmail(session_id.ToString()), login_usr.Email, StringComparison.OrdinalIgnoreCase))
                        //{
                        //    await signInManager.SignOutAsync();
                        //    _context.HttpContext.Session.Remove(session_id);
                        //    TempData["SessionTerminated"] = true;

                        //    _logger.LogInformation($"Terminating previous session for email: {session_id} and {login_usr.Email}");
                        //}

                        // Check if there's an existing session identifier
                        var existingSessionId = _context.HttpContext.Session.GetString("SessionId");
                        var newSessionId = Guid.NewGuid().ToString();
                        await signInManager.PasswordSignInAsync(login_usr.Email, LogModel.Password, false, false);
                        _logger.LogInformation("uirfheifuherf", existingSessionId);

                        if (!string.IsNullOrEmpty(existingSessionId))
                        {
                            _context.HttpContext.Session.Clear();
                            TempData["SessionTerminated"] = true;
                            _logger.LogInformation($"Stop past session -  SessionId: {existingSessionId}");
                            if (user != null)
                            {
                                _context.HttpContext.Session.SetInt32("UserSessionTimeout", session_timeout);

                                _context.HttpContext.Session.SetString("Who_Am_I", user.WhoAmI);
                                _context.HttpContext.Session.SetString("Date_Of_Birth", user.DateOfBirth.ToString());
                                _context.HttpContext.Session.SetString("First_Name", user.First_Name);
                                _context.HttpContext.Session.SetString("Last_Name", user.Last_Name);
                                _context.HttpContext.Session.SetString("NRIC", user.NRIC);

                            }
                            else
                            {
                                _context.HttpContext.Session.SetString("Who_Am_I", "whoami");
                                _context.HttpContext.Session.SetString("Date_Of_Birth", "date");
                                _context.HttpContext.Session.SetString("First_Name", "fn");
                                _context.HttpContext.Session.SetString("Last_Name", "ln");
                                _context.HttpContext.Session.SetString("NRIC", "NRIC");

                            }


                            _context.HttpContext.Session.SetString("SessionId", newSessionId);
                            _context.HttpContext.Session.SetString("User_Email", email_protect);
                            _logger.LogInformation($"Generate a new session with Session id: {newSessionId}");
                        }
                        else
                        {
                            _context.HttpContext.Session.SetString("SessionId", newSessionId);
                            TempData["SessionTerminated"] = false;
                            _context.HttpContext.Session.SetString("User_Email", email_protect);

                            _logger.LogInformation($"Login successful with id: {email_protect}");
                        }
                        await record();
                        return RedirectToPage("/UserDetail");

                    }
                    else
                    {
                        await userManager.AccessFailedAsync(login_usr);

                        if (await userManager.IsLockedOutAsync(login_usr))
                        {
                            var auditLog1 = new AuditLog
                            {
                                UserId = protector.Protect(login_usr.Email),
                                Timestamp = DateTime.UtcNow,
                                Action = "Account is lock"
                            };


                            _dbcontext.AuditLogs.Add(auditLog1);
                            await _dbcontext.SaveChangesAsync();
                            ModelState.AddModelError("", "Account is locked out. Please try again later.");
                            return Page();
                        }
                        ModelState.AddModelError("", "ID or password is Incorrect");


                        var auditLog = new AuditLog
                        {
                            UserId = protector.Protect(login_usr.Email),
                            Timestamp = DateTime.UtcNow,
                            Action = "Enter wrong password"
                        };


                        _dbcontext.AuditLogs.Add(auditLog);
                        await _dbcontext.SaveChangesAsync();

                        _logger.LogInformation($"Incorrect password");
                        return Page();
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Please Enter Password");
                    return Page();
                }

            }
            else
            {
                ModelState.AddModelError("", "ID or password is Incorrect");

                _logger.LogInformation($"Unknown user");
                return Page();

            }
        }


        private string DecryptEmail(string encryptedEmail)
        {
            // Use the appropriate decryption logic here
            var protector = dataProtectionProvider.CreateProtector("EmailAdressProtector");
            return protector.Unprotect(encryptedEmail);
        }




        private async Task record()
        {
            // Log user activity to the database
            var auditLog = new AuditLog
            {
                UserId = _context.HttpContext.Session.GetString("User_Email"),
                Timestamp = DateTime.UtcNow,
                Action = "login"
            };

            _dbcontext.AuditLogs.Add(auditLog);
            await _dbcontext.SaveChangesAsync();
        }






    }
}
