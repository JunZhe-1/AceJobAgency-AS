using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.IO; 
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using WebApplication3.Model;
using WebApplication3.ViewModels;
using static System.Net.WebRequestMethods;

namespace WebApplication3.Pages
{
    public class RegisteRegisteringModel : PageModel
    {

        private UserManager<IdentityUser> userManager { get; }
        private SignInManager<IdentityUser> signInManager { get; }
        //private  DbSet<Register> Registers { get; set; }

        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly AuthDbContext _context; // Add this field

        private readonly ILogger<RegisteRegisteringModel> _logger;



        [BindProperty]
        public Register RegisteringModel { get; set; }

        [BindProperty]
        public IFormFile Resume { get; set; }

        public RegisteRegisteringModel(
           UserManager<IdentityUser> userManager,
           SignInManager<IdentityUser> signInManager,
           IDataProtectionProvider dataProtectionProvider,
            AuthDbContext dbContext,
            ILogger<RegisteRegisteringModel> logger)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.dataProtectionProvider = dataProtectionProvider;
            this._context = dbContext;
            this._logger = logger;

        }



        public void OnGet()
        {
        }



        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            var file_name = "";

            var emailAdressRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}$");
            if (RegisteringModel.Email == null || !emailAdressRegex.IsMatch(RegisteringModel.Email))
            {
                ModelState.AddModelError(nameof(RegisteringModel.Email), "Please enter a valid email address.");
                return Page();
            }



            if (RegisteringModel.First_Name != null && RegisteringModel.Last_Name != null && RegisteringModel.NRIC != null)
            {

                var Name_protector = dataProtectionProvider.CreateProtector("Name");

                var protectFirst_Name = Name_protector.Protect(RegisteringModel.First_Name.ToLower());
                var protectlast_Name = Name_protector.Protect(RegisteringModel.Last_Name.ToLower());

                var Email_protector = dataProtectionProvider.CreateProtector("EmailAdressProtector");
                var email_Regex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
                // Check if the email format is valid
                if (RegisteringModel.Email == null || !email_Regex.IsMatch(RegisteringModel.Email))
                {
                    ModelState.AddModelError(nameof(RegisteringModel.Email), "Please enter a valid email address.");
                    return Page();
                }

                var protectEmail = Email_protector.Protect(RegisteringModel.Email.ToLower());
                var nricRegex = new Regex(@"^[TtSs]\d{7}[A-Za-z]$");
                if (RegisteringModel.NRIC == null || !nricRegex.IsMatch(RegisteringModel.NRIC))
                {
                    ModelState.AddModelError(nameof(RegisteringModel.NRIC), "Please enter a valid NRIC address.");
                    return Page();
                }

                var IC_protector = dataProtectionProvider.CreateProtector("NRIC");
                var ProtectNRIC = IC_protector.Protect(RegisteringModel.NRIC);

                
                var all_email = await _context.Registers.ToListAsync();
                var existingUser = await userManager.Users.FirstOrDefaultAsync(u => u.Email == RegisteringModel.Email);
                var existingUser_register_db = all_email.FirstOrDefault(u => DecryptEmail(u.Email).ToLower() == RegisteringModel.Email.ToLower());



                if (existingUser != null)
                {
                    ModelState.AddModelError(nameof(RegisteringModel.Email), "Email already been used");
                    return Page();
                }
                //else
                //{
                //    ModelState.AddModelError(existingUser_register_db?.ToString());

                //}

                if (RegisteringModel.Password != null)
                {
                    if (!IsStrongPassword(RegisteringModel.Password))
                    {
                        ModelState.AddModelError(nameof(RegisteringModel.Password), "Password must be at least 12 characters long and include a combination of lower-case, upper-case, numbers, and special characters.");
                        return Page();
                    }
                }
                if (Resume != null)
                {
                    long maxSizeOfFileInBytes = 1 * 1024 * 1024; // 5 megabytes

                    if (Resume.Length > maxSizeOfFileInBytes)
                    {
                        ModelState.AddModelError(nameof(Resume), "File size exceeds the allowed limit.");
                        return Page();
                    }
                    string[] allowedExtensions = { ".pdf", ".doc", ".docx" }; // Add the allowed extensions
                    var fileExtension = Path.GetExtension(Resume.FileName).ToLowerInvariant();
                    if (!allowedExtensions.Contains(fileExtension))
                    {
                        ModelState.AddModelError(nameof(Resume), "Incorrect file extension. Allowed extensions are .pdf, .doc, .docx");
                        return Page();
                    }
                    else
                    {
                        file_name = GenerateRandomNumber(fileExtension);


                        var File_Path = file_name;



                        using (var File_Stresm = new FileStream(File_Path, FileMode.Create))
                        {
                            await Resume.CopyToAsync(File_Stresm);
                        }
                    }

                }

                if (RegisteringModel.Password == null)
                {
                    ModelState.AddModelError(nameof(RegisteringModel.Password), "Password is required.");
                    return Page();
                }
                var password_protector = dataProtectionProvider.CreateProtector("PasswordProtector");
                var ProtectPassword = password_protector.Protect(RegisteringModel.Password);


                if (ModelState.IsValid)
                {
                    var user = new IdentityUser()
                    {
                        UserName = RegisteringModel.Email,
                        Email = RegisteringModel.Email
                    };


                    if (!string.IsNullOrEmpty(RegisteringModel.WhoAmI))
                    {
                        // Encode "<" and ">"
                        RegisteringModel.WhoAmI = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(RegisteringModel.WhoAmI);
                    }


                    var register = new Register()
                    {
                        Email = protectEmail,
                        First_Name = protectFirst_Name,
                        Last_Name = protectlast_Name,
                        DateOfBirth = RegisteringModel.DateOfBirth,
                        ConfirmPassword = ProtectPassword,
                        Password = ProtectPassword,
                        NRIC = ProtectNRIC,
                        Gender = RegisteringModel.Gender,
                        WhoAmI = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(RegisteringModel.WhoAmI),
                        ResumeFilePath = file_name, // Set the ResumeFilePath property
                    };



                    // // Assuming db context is available
                    _context.Registers.Add(register);
                    var result1 = await _context.SaveChangesAsync();

                    var result = await userManager.CreateAsync(user, RegisteringModel.Password);

                    if (result1 > 0 && result.Succeeded) // Check if any changes were saved
                    {
                        await signInManager.SignInAsync(user, false);
                        await signInManager.SignOutAsync();
                        return RedirectToPage("Login");
                    }
                    else
                    {
                        // Handle the case where no changes were saved
                        ModelState.AddModelError("", "Error saving data to the database.");
                        return Page();
                    }
                }




            }

            return Page();



        }




        private string GenerateRandomNumber(string fileExtension)
        {
            var random = new Random();
            var randomNumber = random.Next(1, 10001);
            var filePath = Path.Combine(".\\resume", randomNumber + fileExtension);

            if (System.IO.File.Exists(filePath))
            {
                return GenerateRandomNumber(fileExtension);
            }
            else
            {
                return filePath;
            }
        }


        private string DecryptEmail(string encryptedEmail)
        {
            // Use the appropriate decryption logic here
            var protector = dataProtectionProvider.CreateProtector("EmailAdressProtector");
            return protector.Unprotect(encryptedEmail);
        }

        // validate the password, return boolean
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
